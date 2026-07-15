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

	"github.com/schollz/pake/v3"
	"golang.org/x/crypto/chacha20poly1305"
)

// pakeCurve: P-256 explicitly — schollz/pake's default SIEC curve is exotic
// and unreviewed; P-256 is the conservative choice.
const pakeCurve = "p256"

// transcript binds the protocol version and mode into the PAKE input so a
// downgrade cannot go unnoticed.
func transcript(code string) []byte {
	return []byte("xtunnel/1|rendezvous|" + code)
}

// SecureChannel is an AEAD-framed signaling channel over the mailbox, keyed
// by a PAKE run on the room code. A malicious server gets exactly one online
// code guess, which the first frame exchange (key confirmation) exposes.
type SecureChannel struct {
	mb *Mailbox

	sendMu   sync.Mutex
	sendAEAD cipher.AEAD
	sendCtr  uint64

	recvAEAD cipher.AEAD
	recvCtr  uint64
}

// frame is the plaintext inside each AEAD envelope.
type frame struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d,omitempty"`
}

// Secure runs the PAKE over the mailbox and returns the encrypted channel.
// The host must pass isHost=true (PAKE role 0, speaks first).
func Secure(ctx context.Context, mb *Mailbox, code string, isHost bool) (*SecureChannel, error) {
	role := 1
	if isHost {
		role = 0
	}
	p, err := pake.InitCurve(transcript(code), role, pakeCurve)
	if err != nil {
		return nil, fmt.Errorf("init PAKE: %w", err)
	}

	if isHost {
		if err := mb.Send(ctx, p.Bytes()); err != nil {
			return nil, err
		}
		reply, err := mb.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(reply); err != nil {
			return nil, fmt.Errorf("PAKE failed (wrong code?): %w", err)
		}
	} else {
		first, err := mb.Recv(ctx)
		if err != nil {
			return nil, err
		}
		if err := p.Update(first); err != nil {
			return nil, fmt.Errorf("PAKE failed (wrong code?): %w", err)
		}
		if err := mb.Send(ctx, p.Bytes()); err != nil {
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

	sc := &SecureChannel{mb: mb}
	if isHost {
		sc.sendAEAD, sc.recvAEAD = hostAEAD, joinAEAD
	} else {
		sc.sendAEAD, sc.recvAEAD = joinAEAD, hostAEAD
	}
	return sc, nil
}

func nonceFor(ctr uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
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

// Recv decrypts the next signaling message. A decryption failure on the very
// first frame means the two sides derived different PAKE keys — i.e. someone
// used a wrong or guessed room code — and pairing must be aborted.
func (s *SecureChannel) Recv(ctx context.Context) (string, json.RawMessage, error) {
	body, err := s.mb.Recv(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(body) < 8 {
		return "", nil, errors.New("short signaling frame")
	}
	ctr := binary.BigEndian.Uint64(body[:8])
	if ctr != s.recvCtr {
		return "", nil, fmt.Errorf("signaling frame counter mismatch (got %d want %d)", ctr, s.recvCtr)
	}
	plain, err := s.recvAEAD.Open(nil, nonceFor(ctr), body[8:], body[:8])
	if err != nil {
		return "", nil, errors.New("signaling decryption failed — wrong room code or tampering; aborting")
	}
	s.recvCtr++

	var f frame
	if err := json.Unmarshal(plain, &f); err != nil {
		return "", nil, fmt.Errorf("malformed signaling frame: %w", err)
	}
	return f.T, f.D, nil
}

// Close closes the underlying mailbox.
func (s *SecureChannel) Close() error { return s.mb.Close() }
