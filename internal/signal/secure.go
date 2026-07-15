package signal

import (
	"context"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/schollz/pake/v3"
	"golang.org/x/crypto/chacha20poly1305"
)

// pakeCurve: P-256 explicitly — schollz/pake's default SIEC curve is exotic
// and unreviewed; P-256 is the conservative choice.
const pakeCurve = "p256"

// handshakeTimeout bounds the PAKE exchange so a peer that connects and then
// stays silent cannot hang the other side indefinitely.
const handshakeTimeout = 30 * time.Second

// ErrChannelClosed is returned by Recv once the read pump has stopped (mailbox
// closed, decryption failure, or context cancellation).
var ErrChannelClosed = errors.New("signaling channel closed")

// transcript binds the protocol version and mode into the PAKE input so a
// downgrade cannot go unnoticed.
func transcript(code string) []byte {
	return []byte("xtunnel/1|rendezvous|" + code)
}

// SecureChannel is an AEAD-framed signaling channel over the mailbox, keyed by
// a PAKE run on the full pairing code. A read pump owns all mailbox reads for
// the channel's lifetime: it decrypts inbound frames onto a buffered channel,
// which (a) lets Keepalive pings have their pongs processed even while no round
// is actively receiving, and (b) lets a reconnect round drain stale frames
// left over from an aborted round. A malicious server gets exactly one online
// code guess — a wrong guess makes the first frame fail to decrypt.
type SecureChannel struct {
	mb *Mailbox

	sendMu   sync.Mutex
	sendAEAD cipher.AEAD
	sendCtr  uint64

	recvAEAD cipher.AEAD
	recvCtr  uint64

	frames  chan recvFrame
	errMu   sync.Mutex
	pumpErr error
}

// frame is the plaintext inside each AEAD envelope.
type frame struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d,omitempty"`
}

type recvFrame struct {
	t string
	d json.RawMessage
}

// Secure runs the PAKE over the mailbox and returns the encrypted channel.
// The host must pass isHost=true (PAKE role 0, speaks first). ctx bounds the
// channel's whole lifetime (the read pump runs until ctx is cancelled); the
// PAKE exchange itself is additionally bounded by handshakeTimeout.
func Secure(ctx context.Context, mb *Mailbox, code string, isHost bool) (*SecureChannel, error) {
	role := 1
	if isHost {
		role = 0
	}
	p, err := pake.InitCurve(transcript(code), role, pakeCurve)
	if err != nil {
		return nil, fmt.Errorf("init PAKE: %w", err)
	}

	hctx, hcancel := context.WithTimeout(ctx, handshakeTimeout)
	defer hcancel()

	if isHost {
		if err := mb.Send(hctx, p.Bytes()); err != nil {
			return nil, err
		}
		reply, err := mb.Recv(hctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(reply); err != nil {
			return nil, fmt.Errorf("PAKE failed (wrong code?): %w", err)
		}
	} else {
		first, err := mb.Recv(hctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(first); err != nil {
			return nil, fmt.Errorf("PAKE failed (wrong code?): %w", err)
		}
		if err := mb.Send(hctx, p.Bytes()); err != nil {
			return nil, err
		}
	}

	key, err := p.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("PAKE session key: %w", err)
	}

	hostKey, err := hkdf.Key(sha256.New, key, nil, "xtunnel/sig/host->join", chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	joinKey, err := hkdf.Key(sha256.New, key, nil, "xtunnel/sig/join->host", chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	hostAEAD, err := chacha20poly1305.New(hostKey)
	if err != nil {
		return nil, err
	}
	joinAEAD, err := chacha20poly1305.New(joinKey)
	if err != nil {
		return nil, err
	}

	sc := &SecureChannel{mb: mb, frames: make(chan recvFrame, 64)}
	if isHost {
		sc.sendAEAD, sc.recvAEAD = hostAEAD, joinAEAD
	} else {
		sc.sendAEAD, sc.recvAEAD = joinAEAD, hostAEAD
	}
	go sc.pump(ctx)
	return sc, nil
}

func nonceFor(ctr uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// pump reads, decrypts, and buffers inbound frames for the channel's lifetime.
func (s *SecureChannel) pump(ctx context.Context) {
	defer close(s.frames)
	for {
		body, err := s.mb.Recv(ctx)
		if err != nil {
			s.setErr(err)
			return
		}
		if len(body) < 8 {
			s.setErr(errors.New("short signaling frame"))
			return
		}
		ctr := binary.BigEndian.Uint64(body[:8])
		if ctr != s.recvCtr {
			s.setErr(fmt.Errorf("signaling frame counter mismatch (got %d want %d)", ctr, s.recvCtr))
			return
		}
		plain, err := s.recvAEAD.Open(nil, nonceFor(ctr), body[8:], body[:8])
		if err != nil {
			s.setErr(errors.New("signaling decryption failed — wrong room code or tampering; aborting"))
			return
		}
		s.recvCtr++

		var f frame
		if err := json.Unmarshal(plain, &f); err != nil {
			s.setErr(fmt.Errorf("malformed signaling frame: %w", err))
			return
		}
		select {
		case s.frames <- recvFrame{f.T, f.D}:
		case <-ctx.Done():
			s.setErr(ctx.Err())
			return
		}
	}
}

func (s *SecureChannel) setErr(err error) {
	s.errMu.Lock()
	if s.pumpErr == nil {
		s.pumpErr = err
	}
	s.errMu.Unlock()
}

func (s *SecureChannel) err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.pumpErr != nil {
		return s.pumpErr
	}
	return ErrChannelClosed
}

// Send encrypts and relays one typed signaling message.
func (s *SecureChannel) Send(ctx context.Context, msgType string, payload any) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	plain, err := json.Marshal(frame{T: msgType, D: raw})
	if err != nil {
		return err
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	body := make([]byte, 8, 8+len(plain)+s.sendAEAD.Overhead())
	binary.BigEndian.PutUint64(body, s.sendCtr)
	body = s.sendAEAD.Seal(body, nonceFor(s.sendCtr), plain, body[:8])
	s.sendCtr++
	return s.mb.Send(ctx, body)
}

// Recv returns the next decrypted signaling message, blocking until one is
// available, ctx is cancelled, or the channel closes.
func (s *SecureChannel) Recv(ctx context.Context) (string, json.RawMessage, error) {
	select {
	case f, ok := <-s.frames:
		if !ok {
			return "", nil, s.err()
		}
		return f.t, f.d, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

// TryRecv returns a buffered frame without blocking. ok is false if none is
// immediately available (or the channel has closed). Used to drain stale
// frames from aborted reconnect rounds.
func (s *SecureChannel) TryRecv() (msgType string, payload json.RawMessage, ok bool) {
	select {
	case f, chOK := <-s.frames:
		if !chOK {
			return "", nil, false
		}
		return f.t, f.d, true
	default:
		return "", nil, false
	}
}

// Drain discards every currently-buffered frame. Called at the start of a
// reconnect round to clear stragglers left by an aborted round.
func (s *SecureChannel) Drain() {
	for {
		if _, _, ok := s.TryRecv(); !ok {
			return
		}
	}
}

// Close closes the underlying mailbox, which unblocks the read pump.
func (s *SecureChannel) Close() error { return s.mb.Close() }
