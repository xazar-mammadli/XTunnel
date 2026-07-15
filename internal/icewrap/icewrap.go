// Package icewrap wraps pion/ice with the small surface xtunnel needs:
// gather candidates (trickled or all at once), exchange them over any
// signaling channel, and establish a single ice.Conn between two peers.
// It also adapts the established conn to net.PacketConn for quic-go.
package icewrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// TURNServer describes one TURN relay with credentials.
type TURNServer struct {
	// URL in stun URI form, e.g. "turn:relay.example.com:3478?transport=udp".
	URL      string
	Username string
	Password string
}

// Config controls candidate gathering and connectivity behavior.
type Config struct {
	// STUNServers in URI form, e.g. "stun:stun.l.google.com:19302".
	STUNServers []string
	// TURNServers to gather relay candidates from (relay fallback).
	TURNServers []TURNServer

	// LocalUfrag/LocalPwd pin the local ICE credentials. Both empty means
	// random credentials (rendezvous mode); both set is used by manual mode
	// where credentials are derived from the blob seed.
	LocalUfrag string
	LocalPwd   string

	// RelayOnly restricts gathering to relay candidates (forced-relay test mode).
	RelayOnly bool
	// IncludeLoopback admits loopback interfaces; used in tests.
	IncludeLoopback bool
	// UDP4Only restricts gathering to IPv4; used in tests for determinism.
	UDP4Only bool

	// DisconnectedTimeout / FailedTimeout override pion defaults (5s / 25s).
	DisconnectedTimeout time.Duration
	FailedTimeout       time.Duration
}

// Endpoint owns one ICE agent for the lifetime of one peer connection.
type Endpoint struct {
	agent *ice.Agent

	candCh     chan ice.Candidate
	gatherDone chan struct{}
	gathering  bool
}

// New builds the underlying agent. Call StartGather before consuming
// Candidates or GatherAll.
func New(cfg Config) (*Endpoint, error) {
	var urls []*stun.URI
	for _, s := range cfg.STUNServers {
		u, err := stun.ParseURI(s)
		if err != nil {
			return nil, fmt.Errorf("parse STUN url %q: %w", s, err)
		}
		urls = append(urls, u)
	}
	for _, t := range cfg.TURNServers {
		u, err := stun.ParseURI(t.URL)
		if err != nil {
			return nil, fmt.Errorf("parse TURN url %q: %w", t.URL, err)
		}
		u.Username = t.Username
		u.Password = t.Password
		urls = append(urls, u)
	}

	networkTypes := []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6}
	if cfg.UDP4Only {
		networkTypes = []ice.NetworkType{ice.NetworkTypeUDP4}
	}

	agentCfg := &ice.AgentConfig{
		Urls:            urls,
		NetworkTypes:    networkTypes,
		LocalUfrag:      cfg.LocalUfrag,
		LocalPwd:        cfg.LocalPwd,
		IncludeLoopback: cfg.IncludeLoopback,
	}
	if cfg.RelayOnly {
		agentCfg.CandidateTypes = []ice.CandidateType{ice.CandidateTypeRelay}
	}
	if cfg.DisconnectedTimeout > 0 {
		agentCfg.DisconnectedTimeout = &cfg.DisconnectedTimeout
	}
	if cfg.FailedTimeout > 0 {
		agentCfg.FailedTimeout = &cfg.FailedTimeout
	}

	agent, err := ice.NewAgent(agentCfg)
	if err != nil {
		return nil, fmt.Errorf("create ICE agent: %w", err)
	}

	return &Endpoint{
		agent:      agent,
		candCh:     make(chan ice.Candidate, 32),
		gatherDone: make(chan struct{}),
	}, nil
}

// Credentials returns the local ufrag/pwd to send to the remote peer.
func (e *Endpoint) Credentials() (ufrag, pwd string, err error) {
	return e.agent.GetLocalUserCredentials()
}

// StartGather begins candidate gathering. Discovered candidates are delivered
// on Candidates; the channel is closed when gathering completes.
func (e *Endpoint) StartGather() error {
	if e.gathering {
		return errors.New("gathering already started")
	}
	e.gathering = true
	if err := e.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(e.gatherDone)
			close(e.candCh)
			return
		}
		select {
		case e.candCh <- c:
		default:
			// Channel full: drop rather than block pion's internal loop.
			// 32 slots is far beyond any realistic candidate count.
		}
	}); err != nil {
		return fmt.Errorf("set candidate handler: %w", err)
	}
	if err := e.agent.GatherCandidates(); err != nil {
		return fmt.Errorf("gather candidates: %w", err)
	}
	return nil
}

// Candidates streams trickled local candidates. Closed when gathering ends.
func (e *Endpoint) Candidates() <-chan ice.Candidate { return e.candCh }

// GatherAll starts gathering (if needed) and blocks until it completes or ctx
// expires, returning every discovered candidate. Used by manual mode where
// the full set must be embedded in one blob.
func (e *Endpoint) GatherAll(ctx context.Context) ([]ice.Candidate, error) {
	if !e.gathering {
		if err := e.StartGather(); err != nil {
			return nil, err
		}
	}
	var out []ice.Candidate
	for {
		select {
		case c, ok := <-e.candCh:
			if !ok {
				return out, nil
			}
			out = append(out, c)
		case <-ctx.Done():
			// Timed out waiting for the full gather (e.g. unreachable STUN
			// server). Return what we have — partial candidates still work.
			for {
				select {
				case c, ok := <-e.candCh:
					if !ok {
						return out, nil
					}
					out = append(out, c)
				default:
					return out, nil
				}
			}
		}
	}
}

// AddRemoteCandidate registers a candidate received from the remote peer,
// in the SDP attribute form produced by ice.Candidate.Marshal().
func (e *Endpoint) AddRemoteCandidate(raw string) error {
	c, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		return fmt.Errorf("unmarshal candidate %q: %w", raw, err)
	}
	return e.agent.AddRemoteCandidate(c)
}

// AddRemoteCandidateObj registers an already-constructed remote candidate
// (used by manual mode, which rebuilds candidates from blob form).
func (e *Endpoint) AddRemoteCandidateObj(c ice.Candidate) error {
	return e.agent.AddRemoteCandidate(c)
}

// Dial runs connectivity checks as the controlling agent.
func (e *Endpoint) Dial(ctx context.Context, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	return e.agent.Dial(ctx, remoteUfrag, remotePwd)
}

// Accept runs connectivity checks as the controlled agent.
func (e *Endpoint) Accept(ctx context.Context, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	return e.agent.Accept(ctx, remoteUfrag, remotePwd)
}

// OnConnectionStateChange forwards pion's state callbacks (logging/UX).
func (e *Endpoint) OnConnectionStateChange(f func(ice.ConnectionState)) error {
	return e.agent.OnConnectionStateChange(f)
}

// SelectedPair reports the nominated candidate pair, nil before nomination.
func (e *Endpoint) SelectedPair() (*ice.CandidatePair, error) {
	return e.agent.GetSelectedCandidatePair()
}

// Close releases the agent and every gathered socket.
func (e *Endpoint) Close() error { return e.agent.Close() }
