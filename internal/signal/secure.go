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

const (
	pakeCurve        = "p256"
	handshakeTimeout = 30 * time.Second
)

var (
	ErrChannelClosed = errors.New("signaling channel closed")
	ErrWrongCode     = errors.New("wrong code")
)

type Transport interface {
	Send(ctx context.Context, body []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
}

func transcript(code string) []byte {
	return []byte("xtunnel/1|" + code)
}

type SecureChannel struct {
	t Transport

	sendMu   sync.Mutex
	sendAEAD cipher.AEAD
	sendCtr  uint64

	recvAEAD cipher.AEAD
	recvCtr  uint64

	frames  chan recvFrame
	errMu   sync.Mutex
	pumpErr error
}

type frame struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d,omitempty"`
}

type recvFrame struct {
	t string
	d json.RawMessage
}

func Secure(ctx context.Context, t Transport, code string, isHost bool) (*SecureChannel, error) {
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
		if err := t.Send(hctx, p.Bytes()); err != nil {
			return nil, err
		}
		reply, err := t.Recv(hctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(reply); err != nil {
			return nil, fmt.Errorf("pairing handshake failed: %w", err)
		}
	} else {
		first, err := t.Recv(hctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(first); err != nil {
			return nil, fmt.Errorf("pairing handshake failed: %w", err)
		}
		if err := t.Send(hctx, p.Bytes()); err != nil {
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

	sc := &SecureChannel{t: t, frames: make(chan recvFrame, 64)}
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

func (s *SecureChannel) pump(ctx context.Context) {
	defer close(s.frames)
	for {
		body, err := s.t.Recv(ctx)
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
			s.setErr(ErrWrongCode)
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

func (s *SecureChannel) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.pumpErr
}

func (s *SecureChannel) err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.pumpErr != nil {
		return s.pumpErr
	}
	return ErrChannelClosed
}

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
	return s.t.Send(ctx, body)
}

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

func (s *SecureChannel) Drain() {
	for {
		if _, _, ok := s.TryRecv(); !ok {
			return
		}
	}
}

func (s *SecureChannel) Close() error { return s.t.Close() }
