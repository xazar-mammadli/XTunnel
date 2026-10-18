package signal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

var ErrPeerLeft = errors.New("peer left the room")

const writeTimeout = 15 * time.Second

type DialError struct {
	Server string
	Status int
	Body   string
	Err    error
}

func (e *DialError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("connect to %s: HTTP %d", e.Server, e.Status)
	}
	return fmt.Sprintf("connect to %s: %v", e.Server, e.Err)
}

func (e *DialError) Unwrap() error { return e.Err }

type ServerError struct {
	Msg string
}

func (e *ServerError) Error() string { return "server: " + e.Msg }

type Mailbox struct {
	ws        *websocket.Conn
	sendMu    sync.Mutex
	turn      []TURNCred
	reconnect bool
}

func Create(ctx context.Context, server string) (*Mailbox, string, error) {
	m, err := dial(ctx, server, url.Values{"op": {"create"}})
	if err != nil {
		return nil, "", err
	}
	env, err := m.handshake(ctx, &Envelope{Type: "create"}, "created")
	if err != nil {
		_ = m.Close()
		return nil, "", err
	}
	if !ValidNameplate(env.Room) {
		_ = m.Close()
		return nil, "", fmt.Errorf("server assigned an invalid room %q", env.Room)
	}
	return m, env.Room, nil
}

func Join(ctx context.Context, server, nameplate string) (*Mailbox, error) {
	m, err := dial(ctx, server, url.Values{"op": {"join"}, "room": {nameplate}})
	if err != nil {
		return nil, err
	}
	if _, err := m.handshake(ctx, &Envelope{Type: "join", Room: nameplate}, "joined"); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func endpoint(server string) (*url.URL, error) {
	if !strings.Contains(server, "://") {
		server = "wss://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	switch u.Scheme {
	case "http", "ws":
		u.Scheme = "ws"
	case "https", "wss":
		u.Scheme = "wss"
	default:
		return nil, fmt.Errorf("unsupported server URL scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("server URL %q has no host", server)
	}
	if !strings.HasSuffix(u.Path, "/ws") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/ws"
	}
	return u, nil
}

func dial(ctx context.Context, server string, query url.Values) (*Mailbox, error) {
	u, err := endpoint(server)
	if err != nil {
		return nil, err
	}
	u.RawQuery = query.Encode()
	ws, resp, err := websocket.Dial(ctx, u.String(), nil)
	if err != nil {
		de := &DialError{Server: server, Err: err}
		if resp != nil {
			de.Status = resp.StatusCode
			if resp.Body != nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				de.Body = strings.TrimSpace(string(b))
			}
		}
		return nil, de
	}
	ws.SetReadLimit(1 << 20)
	return &Mailbox{ws: ws}, nil
}

func (m *Mailbox) handshake(ctx context.Context, req *Envelope, want string) (*Envelope, error) {
	if err := m.write(ctx, req); err != nil {
		return nil, err
	}
	env, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	if env.Type != want {
		return nil, fmt.Errorf("unexpected server reply %q", env.Type)
	}
	m.turn = env.TURN
	m.reconnect = env.Reconnect
	return env, nil
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
		return nil, &ServerError{Msg: env.Err}
	}
	return &env, nil
}

func (m *Mailbox) TURNServers() []TURNCred { return m.turn }

func (m *Mailbox) Reconnect() bool { return m.reconnect }

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

func (m *Mailbox) Send(ctx context.Context, body []byte) error {
	return m.write(ctx, &Envelope{Type: "msg", Body: body})
}

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
		}
	}
}

func (m *Mailbox) Keepalive(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := m.ws.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (m *Mailbox) Close() error {
	return m.ws.Close(websocket.StatusNormalClosure, "bye")
}
