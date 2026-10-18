package mailbox

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

	"github.com/xazar-mammadli/XTunnel/internal/signal"
)

const (
	unpairedTTL        = 10 * time.Minute
	pairedTTL          = 24 * time.Hour
	writeTimeout       = 15 * time.Second
	maxMsgSize         = 1 << 20
	maxNameplateTries  = 64
	limiterBurst       = 20
	limiterReplenishes = 3 * time.Second
)

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
	slots  [2]*peerSlot
	burned bool
}

type TURNIssuer interface {
	Issue(ttl time.Duration) (signal.TURNCred, bool)
}

type Server struct {
	mu    sync.Mutex
	rooms map[string]*room

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	turn TURNIssuer
}

func New(issuer TURNIssuer) *Server {
	m := &Server{
		rooms:    make(map[string]*room),
		limiters: make(map[string]*rate.Limiter),
		turn:     issuer,
	}
	go m.janitor()
	return m
}

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

func (m *Server) limiter(ip string) *rate.Limiter {
	m.limMu.Lock()
	defer m.limMu.Unlock()
	l, ok := m.limiters[ip]
	if !ok {
		l = rate.NewLimiter(rate.Every(limiterReplenishes), limiterBurst)
		m.limiters[ip] = l
	}
	return l
}

func (m *Server) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()

		var toClose []*peerSlot
		m.mu.Lock()
		for code, r := range m.rooms {
			r.mu.Lock()
			paired := r.slots[0] != nil && r.slots[1] != nil
			expired := (!paired && now.Sub(r.created) > unpairedTTL) ||
				now.Sub(r.created) > pairedTTL
			if expired {
				r.burned = true
				for _, s := range r.slots {
					if s != nil {
						toClose = append(toClose, s)
					}
				}
				r.slots = [2]*peerSlot{}
			}
			r.mu.Unlock()
			if expired {
				delete(m.rooms, code)
			}
		}
		m.mu.Unlock()

		for _, s := range toClose {
			_ = s.ws.CloseNow()
		}

		m.limMu.Lock()
		for ip, l := range m.limiters {
			if l.Tokens() >= limiterBurst {
				delete(m.limiters, ip)
			}
		}
		m.limMu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (m *Server) HandleWS(w http.ResponseWriter, req *http.Request) {
	ws, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(maxMsgSize)
	slot := &peerSlot{ws: ws}
	ctx := req.Context()
	defer ws.CloseNow()

	first, err := readEnvelope(ctx, ws, 30*time.Second)
	if err != nil {
		return
	}

	switch first.Type {
	case "create", "join":
		if !m.limiter(clientIP(req)).Allow() {
			_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "rate limited"})
			return
		}
	default:
		_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "expected create or join"})
		return
	}
	if first.Type == "create" {
		m.serveCreator(ctx, slot)
		return
	}
	m.serveJoiner(ctx, slot, first.Room)
}

func (m *Server) serveCreator(ctx context.Context, slot *peerSlot) {
	var code string
	var r *room
	m.mu.Lock()
	for attempt := 0; attempt < maxNameplateTries && r == nil; attempt++ {
		c, err := signal.NewNameplate(attempt)
		if err != nil {
			break
		}
		if _, taken := m.rooms[c]; !taken {
			code = c
			r = &room{code: c, created: time.Now()}
			r.slots[0] = slot
			m.rooms[c] = r
		}
	}
	m.mu.Unlock()
	if r == nil {
		_ = slot.send(ctx, &signal.Envelope{Type: "error", Err: "no free room, try again"})
		return
	}
	log.Printf("room %s created", code)

	created := &signal.Envelope{Type: "created", Room: code, TURN: m.turnCreds(), Reconnect: true}
	if err := slot.send(ctx, created); err != nil {
		m.dropPeer(code, r, 0)
		return
	}
	m.relayLoop(ctx, code, r, 0, slot)
}

func (m *Server) serveJoiner(ctx context.Context, slot *peerSlot, code string) {
	if !signal.ValidNameplate(code) {
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

	if host := r.peer(0); host != nil {
		_ = host.send(ctx, &signal.Envelope{Type: "peer"})
	}
	joined := &signal.Envelope{Type: "joined", TURN: m.turnCreds(), Reconnect: true}
	if err := slot.send(ctx, joined); err != nil {
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

func (m *Server) relayLoop(ctx context.Context, code string, r *room, idx int, slot *peerSlot) {
	defer m.dropPeer(code, r, idx)
	for {
		env, err := readEnvelope(ctx, slot.ws, pairedTTL)
		if err != nil {
			return
		}
		if env.Type != "msg" {
			continue
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

func (m *Server) dropPeer(code string, r *room, idx int) {
	r.mu.Lock()
	r.slots[idx] = nil
	other := r.slots[1-idx]
	r.mu.Unlock()

	if other != nil {
		_ = other.send(context.Background(), &signal.Envelope{Type: "peer-left"})
		return
	}
	m.mu.Lock()
	if m.rooms[code] == r {
		delete(m.rooms, code)
		log.Printf("room %s closed", code)
	}
	m.mu.Unlock()
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
