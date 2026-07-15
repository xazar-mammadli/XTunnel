package mailbox

// Package mailbox implements the xtunneld room registry and relay.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/xazar/xtunnel/internal/signal"
)

const (
	// unpairedTTL is how long a room waits for its second peer.
	unpairedTTL = 10 * time.Minute
	// pairedTTL caps the total lifetime of a room (signaling only; the
	// P2P tunnel itself outlives the room).
	pairedTTL    = 24 * time.Hour
	writeTimeout = 15 * time.Second
	maxMsgSize   = 1 << 20
)

// peerSlot is one side of a room.
type peerSlot struct {
	ws     *websocket.Conn
	sendMu sync.Mutex
}

func (p *peerSlot) send(ctx context.Context, env *signal.Envelope) error {
	buf, err := json.Marshal(env)
	if err != nil {
		return err
	}
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return p.ws.Write(wctx, websocket.MessageText, buf)
}

type room struct {
	code    string
	created time.Time

	mu     sync.Mutex
	slots  [2]*peerSlot // 0 = creator (host), 1 = joiner
	burned bool
}

// TURNIssuer mints ephemeral relay credentials for peers. Implemented by
// internal/relay; nil when the server runs without an embedded relay.
type TURNIssuer interface {
	Issue(ttl time.Duration) (signal.TURNCred, bool)
}

// mailbox is the in-memory room registry. Nothing is ever persisted.
type Server struct {
	mu    sync.Mutex
	rooms map[string]*room

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	turn TURNIssuer
}

// New builds a mailbox. issuer may be nil (no relay fallback offered).
func New(issuer TURNIssuer) *Server {
	m := &Server{
		rooms:    make(map[string]*room),
		limiters: make(map[string]*rate.Limiter),
		turn:     issuer,
	}
	go m.janitor()
	return m
}

// turnCreds returns freshly issued relay credentials, or nil if no relay.
func (m *Server) turnCreds() []signal.TURNCred {
	if m.turn == nil {
		return nil
	}
	cred, ok := m.turn.Issue(0)
	if !ok {
		return nil
	}
	return []signal.TURNCred{cred}
}

// limiter returns the per-IP rate limiter for room create/join operations.
func (m *Server) limiter(ip string) *rate.Limiter {
	m.limMu.Lock()
	defer m.limMu.Unlock()
	l, ok := m.limiters[ip]
	if !ok {
		// Burst 20, then one operation per 3 seconds.
		l = rate.NewLimiter(rate.Every(3*time.Second), 20)
		m.limiters[ip] = l
	}
	return l
}

func (m *Server) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		m.mu.Lock()
		for code, r := range m.rooms {
			r.mu.Lock()
			paired := r.slots[0] != nil && r.slots[1] != nil
			expired := (!paired && now.Sub(r.created) > unpairedTTL) ||
				now.Sub(r.created) > pairedTTL
			r.mu.Unlock()
			if expired {
				m.closeRoom(code, r, "room expired")
			}
		}
		m.mu.Unlock()

		// Trim the limiter map so idle IPs do not accumulate forever.
		m.limMu.Lock()
		for ip, l := range m.limiters {
			if l.Tokens() >= 20 {
				delete(m.limiters, ip)
			}
		}
		m.limMu.Unlock()
	}
}

// closeRoom must be called with m.mu held.
func (m *Server) closeRoom(code string, r *room, reason string) {
	r.mu.Lock()
	r.burned = true
	slots := r.slots
	r.slots = [2]*peerSlot{}
	r.mu.Unlock()
	for _, s := range slots {
		if s != nil {
			_ = s.ws.Close(websocket.StatusGoingAway, reason)
		}
	}
	delete(m.rooms, code)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleWS serves one signaling connection for its whole lifetime.
func (m *Server) HandleWS(w http.ResponseWriter, req *http.Request) {
	ws, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"}, // clients are CLIs, not browsers
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(maxMsgSize)
	slot := &peerSlot{ws: ws}
	ctx := req.Context()
	defer ws.CloseNow()

	// First envelope decides everything: create or join.
	first, err := readEnvelope(ctx, ws, 30*time.Second)
	if err != nil {
		return
	}

	ip := clientIP(req)
	switch first.Type {
	case "create":
		if !m.limiter(ip).Allow() {
			_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "rate limited"})
			return
		}
		m.serveCreator(ctx, slot)
	case "join":
		if !m.limiter(ip).Allow() {
			_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "rate limited"})
			return
		}
		m.serveJoiner(ctx, slot, first.Room)
	default:
		_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "expected create or join"})
	}
}

func (m *Server) serveCreator(ctx context.Context, slot *peerSlot) {
	var code string
	var r *room
	m.mu.Lock()
	for {
		c, err := signal.NewRoomCode()
		if err != nil {
			m.mu.Unlock()
			_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "internal error"})
			return
		}
		if _, taken := m.rooms[c]; !taken {
			code = c
			r = &room{code: c, created: time.Now()}
			r.slots[0] = slot
			m.rooms[c] = r
			break
		}
	}
	m.mu.Unlock()
	log.Printf("room %s created", code)

	if err := slot.send(ctx, &signal.Envelope{Type: "created", Room: code, TURN: m.turnCreds()}); err != nil {
		m.dropPeer(code, r, 0)
		return
	}
	m.relayLoop(ctx, code, r, 0, slot)
}

func (m *Server) serveJoiner(ctx context.Context, slot *peerSlot, code string) {
	if !signal.ValidRoomCode(code) {
		_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "invalid room code"})
		return
	}
	m.mu.Lock()
	r := m.rooms[code]
	m.mu.Unlock()
	joinErr := ""
	if r == nil {
		joinErr = "no such room (codes are one-time and expire)"
	} else {
		r.mu.Lock()
		switch {
		case r.burned:
			joinErr = "room is closed"
		case r.slots[1] != nil:
			joinErr = "room is full"
		case r.slots[0] == nil:
			joinErr = "room creator is gone"
		default:
			r.slots[1] = slot
		}
		r.mu.Unlock()
	}
	if joinErr != "" {
		_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: joinErr})
		return
	}
	log.Printf("room %s paired", code)

	host := r.peer(0)
	if host != nil {
		_ = host.send(ctx, &signal.Envelope{Type: "peer"})
	}
	if err := slot.send(ctx, &signal.Envelope{Type: "joined", TURN: m.turnCreds()}); err != nil {
		m.dropPeer(code, r, 1)
		return
	}
	m.relayLoop(ctx, code, r, 1, slot)
}

func (r *room) peer(i int) *peerSlot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.slots[i]
}

// relayLoop forwards opaque msg envelopes to the other slot until the
// connection dies.
func (m *Server) relayLoop(ctx context.Context, code string, r *room, idx int, slot *peerSlot) {
	defer m.dropPeer(code, r, idx)
	for {
		env, err := readEnvelope(ctx, slot.ws, pairedTTL)
		if err != nil {
			return
		}
		if env.Type != "msg" {
			continue // only relaying is supported after setup
		}
		other := r.peer(1 - idx)
		if other == nil {
			_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "peer not connected"})
			continue
		}
		env.Room = ""
		if err := other.send(ctx, env); err != nil {
			return
		}
	}
}

// dropPeer detaches one slot; the room dies when both slots are gone, and
// the remaining peer is told immediately.
func (m *Server) dropPeer(code string, r *room, idx int) {
	r.mu.Lock()
	if r.slots[idx] != nil {
		r.slots[idx] = nil
	}
	other := r.slots[1-idx]
	empty := other == nil
	r.mu.Unlock()

	if other != nil {
		_ = other.send(context.Background(), &signal.Envelope{Type: "peer-left"})
	}
	if empty {
		m.mu.Lock()
		if m.rooms[code] == r {
			delete(m.rooms, code)
			log.Printf("room %s closed", code)
		}
		m.mu.Unlock()
	}
}

func readEnvelope(ctx context.Context, ws *websocket.Conn, timeout time.Duration) (*signal.Envelope, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, buf, err := ws.Read(rctx)
	if err != nil {
		return nil, err
	}
	var env signal.Envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, errors.New("malformed envelope")
	}
	return &env, nil
}
