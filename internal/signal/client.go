package signal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ErrPeerLeft is returned by Recv when the remote peer disconnected from the
// mailbox during pairing.
var ErrPeerLeft = errors.New("peer left the room")

const writeTimeout = 15 * time.Second

// Mailbox is a client connection to xtunneld's signaling endpoint.
type Mailbox struct {
	ws *websocket.Conn

	sendMu sync.Mutex
}

// DialMailbox connects to an xtunneld server. Accepts ws://, wss://, http://
// or https:// URLs, with or without the /ws path.
func DialMailbox(ctx context.Context, server string) (*Mailbox, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	switch u.Scheme {
	case "http", "ws":
		u.Scheme = "ws"
	case "https", "wss", "":
		u.Scheme = "wss"
	default:
		return nil, fmt.Errorf("unsupported server URL scheme %q", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/ws") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/ws"
	}

	ws, _, err := websocket.Dial(ctx, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", u, err)
	}
	ws.SetReadLimit(1 << 20)
	return &Mailbox{ws: ws}, nil
}

func (m *Mailbox) write(ctx context.Context, env *Envelope) error {
	buf, err := json.Marshal(env)
	if err != nil {
		return err
	}
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return m.ws.Write(wctx, websocket.MessageText, buf)
}

func (m *Mailbox) read(ctx context.Context) (*Envelope, error) {
	_, buf, err := m.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, fmt.Errorf("malformed server message: %w", err)
	}
	if env.Type == "error" {
		return nil, fmt.Errorf("server: %s", env.Err)
	}
	return &env, nil
}

// CreateRoom asks the server for a fresh one-time room code.
func (m *Mailbox) CreateRoom(ctx context.Context) (string, error) {
	if err := m.write(ctx, &Envelope{Type: "create"}); err != nil {
		return "", err
	}
	env, err := m.read(ctx)
	if err != nil {
		return "", err
	}
	if env.Type != "created" || env.Room == "" {
		return "", fmt.Errorf("unexpected server reply %q", env.Type)
	}
	return env.Room, nil
}

// JoinRoom claims the second slot of an existing room.
func (m *Mailbox) JoinRoom(ctx context.Context, code string) error {
	if err := m.write(ctx, &Envelope{Type: "join", Room: code}); err != nil {
		return err
	}
	env, err := m.read(ctx)
	if err != nil {
		return err
	}
	if env.Type != "joined" {
		return fmt.Errorf("unexpected server reply %q", env.Type)
	}
	return nil
}

// WaitPeer blocks (host side) until a second peer joins the room.
func (m *Mailbox) WaitPeer(ctx context.Context) error {
	env, err := m.read(ctx)
	if err != nil {
		return err
	}
	if env.Type != "peer" {
		return fmt.Errorf("unexpected server message %q while waiting for peer", env.Type)
	}
	return nil
}

// Send relays an opaque payload to the other peer in the room.
func (m *Mailbox) Send(ctx context.Context, body []byte) error {
	return m.write(ctx, &Envelope{Type: "msg", Body: body})
}

// Recv returns the next opaque payload from the other peer.
func (m *Mailbox) Recv(ctx context.Context) ([]byte, error) {
	for {
		env, err := m.read(ctx)
		if err != nil {
			return nil, err
		}
		switch env.Type {
		case "msg":
			return env.Body, nil
		case "peer-left":
			return nil, ErrPeerLeft
		default:
			// Ignore anything else (future extensions, keepalives).
		}
	}
}

// Close tears down the WebSocket.
func (m *Mailbox) Close() error {
	return m.ws.Close(websocket.StatusNormalClosure, "bye")
}
