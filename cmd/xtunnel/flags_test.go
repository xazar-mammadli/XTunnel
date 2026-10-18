package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	sig "github.com/xazar-mammadli/XTunnel/internal/signal"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

func TestParseForward(t *testing.T) {
	cases := []struct {
		in     string
		listen string
		port   uint16
	}{
		{"5432", "127.0.0.1:5432", 5432},
		{"15432:5432", "127.0.0.1:15432", 5432},
		{"0.0.0.0:8080:80", "0.0.0.0:8080", 80},
	}
	for _, c := range cases {
		f, err := parseForward(c.in)
		if err != nil {
			t.Fatalf("parseForward(%q): %v", c.in, err)
		}
		if f.Listen != c.listen || f.Port != c.port {
			t.Fatalf("parseForward(%q) = %+v", c.in, f)
		}
	}
	for _, bad := range []string{"", "0", "70000", "a:b", "1:2:3:4", "8080:"} {
		if _, err := parseForward(bad); err == nil {
			t.Errorf("parseForward(%q) should fail", bad)
		}
	}
}

func TestParseArgsInterleaved(t *testing.T) {
	var o options
	pos, err := parseArgs(newFlagSet("share", &o), []string{"5432", "--server", "wss://relay.example", "8080", "-v", "--timeout", "2m"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pos, []string{"5432", "8080"}) {
		t.Fatalf("positional = %v", pos)
	}
	if o.server != "wss://relay.example" || !o.verbose || o.timeout.Minutes() != 2 {
		t.Fatalf("flags not parsed: %+v", o)
	}

	if _, err := parseArgs(newFlagSet("share", &o), []string{"--bogus"}); !errors.As(err, new(usageError)) {
		t.Fatalf("unknown flag should be a usage error, got %v", err)
	}
	if _, err := parseArgs(newFlagSet("share", &o), []string{"-h"}); !errors.Is(err, errHelp) {
		t.Fatalf("-h should request help, got %v", err)
	}
}

func TestParsePortsDeduplicates(t *testing.T) {
	ports, err := parsePorts([]string{"5432", "8080", "5432"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ports, []uint16{5432, 8080}) {
		t.Fatalf("ports = %v", ports)
	}
	if _, err := parsePorts([]string{"http"}); err == nil {
		t.Fatal("non-numeric port should fail")
	}
}

func TestServerURLPrecedence(t *testing.T) {
	t.Setenv("XTUNNEL_SERVER", "")
	old := defaultServer
	t.Cleanup(func() { defaultServer = old })

	defaultServer = ""
	if _, err := (&options{}).serverURL(); err == nil {
		t.Fatal("no server configured should be an error")
	}
	defaultServer = "wss://default.example"
	if got, _ := (&options{}).serverURL(); got != defaultServer {
		t.Fatalf("got %q, want default", got)
	}
	t.Setenv("XTUNNEL_SERVER", "wss://env.example")
	if got, _ := (&options{}).serverURL(); got != "wss://env.example" {
		t.Fatalf("got %q, want env", got)
	}
	if got, _ := (&options{server: "wss://flag.example"}).serverURL(); got != "wss://flag.example" {
		t.Fatalf("got %q, want flag", got)
	}
}

func TestFriendlyErrors(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&sig.DialError{Server: "wss://r", Status: http.StatusTooManyRequests}, "daily limit"},
		{&sig.DialError{Server: "wss://r", Err: errors.New("dns")}, "cannot reach"},
		{&sig.ServerError{Msg: "no such room (codes are one-time and expire)"}, "does not exist"},
		{&sig.ServerError{Msg: "room is full"}, "already used"},
		{fmt.Errorf("round: %w", sig.ErrWrongCode), "wrong code"},
		{fmt.Errorf("%w: ice", errNoPath), "TURN"},
		{&tunnel.ListenError{Addr: "127.0.0.1:5432", Port: 5432, Err: errors.New("in use")}, "15432:5432"},
	}
	for _, c := range cases {
		if got := friendly(c.err); !strings.Contains(got, c.want) {
			t.Errorf("friendly(%v) = %q, want it to mention %q", c.err, got, c.want)
		}
	}
	if altPort(60000) != 50000 {
		t.Errorf("altPort(60000) = %d", altPort(60000))
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		10 * time.Minute:        "10 minutes",
		time.Minute:             "1 minute",
		90 * time.Second:        "90 seconds",
		2 * time.Hour:           "2 hours",
		1500 * time.Millisecond: "1.5s",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestCheckListenRejectsBusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := uint16(busy.Addr().(*net.TCPAddr).Port)
	err = checkListen([]tunnel.Forward{{Listen: busy.Addr().String(), Port: port}})
	var le *tunnel.ListenError
	if !errors.As(err, &le) || le.Port != port {
		t.Fatalf("expected ListenError for the busy port, got %v", err)
	}
	if err := checkListen([]tunnel.Forward{{Listen: "127.0.0.1:0", Port: 1}}); err != nil {
		t.Fatalf("free port rejected: %v", err)
	}
}
