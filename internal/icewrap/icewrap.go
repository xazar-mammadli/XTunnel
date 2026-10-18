package icewrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

type TURNServer struct {
	URL      string
	Username string
	Password string
}

type Config struct {
	STUNServers []string
	TURNServers []TURNServer

	LocalUfrag string
	LocalPwd   string

	RelayOnly       bool
	IncludeLoopback bool
	UDP4Only        bool

	DisconnectedTimeout time.Duration
	FailedTimeout       time.Duration
}

type Endpoint struct {
	agent *ice.Agent

	candCh     chan ice.Candidate
	gatherDone chan struct{}
	gathering  bool
}

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

func (e *Endpoint) Credentials() (ufrag, pwd string, err error) {
	return e.agent.GetLocalUserCredentials()
}

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
		}
	}); err != nil {
		return fmt.Errorf("set candidate handler: %w", err)
	}
	if err := e.agent.GatherCandidates(); err != nil {
		return fmt.Errorf("gather candidates: %w", err)
	}
	return nil
}

func (e *Endpoint) Candidates() <-chan ice.Candidate { return e.candCh }

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

func (e *Endpoint) AddRemoteCandidate(raw string) error {
	c, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		return fmt.Errorf("unmarshal candidate %q: %w", raw, err)
	}
	return e.agent.AddRemoteCandidate(c)
}

func (e *Endpoint) AddRemoteCandidateObj(c ice.Candidate) error {
	return e.agent.AddRemoteCandidate(c)
}

func (e *Endpoint) Dial(ctx context.Context, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	return e.agent.Dial(ctx, remoteUfrag, remotePwd)
}

func (e *Endpoint) Accept(ctx context.Context, remoteUfrag, remotePwd string) (*ice.Conn, error) {
	return e.agent.Accept(ctx, remoteUfrag, remotePwd)
}

func (e *Endpoint) OnConnectionStateChange(f func(ice.ConnectionState)) error {
	return e.agent.OnConnectionStateChange(f)
}

func (e *Endpoint) SelectedPair() (*ice.CandidatePair, error) {
	return e.agent.GetSelectedCandidatePair()
}

func (e *Endpoint) Close() error { return e.agent.Close() }
