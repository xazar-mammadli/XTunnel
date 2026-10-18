package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/ice/v4"

	"github.com/xazar-mammadli/XTunnel/internal/icewrap"
	"github.com/xazar-mammadli/XTunnel/internal/tunnel"
)

type console struct {
	out     io.Writer
	err     io.Writer
	verbose bool
}

func newConsole(verbose bool) *console {
	return &console{out: os.Stdout, err: os.Stderr, verbose: verbose}
}

func (c *console) say(format string, a ...any) {
	fmt.Fprintf(c.err, format+"\n", a...)
}

func (c *console) debugf(format string, a ...any) {
	if c.verbose {
		fmt.Fprintf(c.err, "  "+format+"\n", a...)
	}
}

func (c *console) logf() tunnel.Logf {
	if c.verbose {
		return c.debugf
	}
	return nil
}

func (c *console) showCode(code string) {
	fmt.Fprintf(c.out, "\nCode: %s\n\nOn the other machine, run:\n\n    xtunnel connect %s\n\n", code, code)
}

func (c *console) showBlob(intro, code string) {
	c.say("%s", intro)
	fmt.Fprintf(c.out, "\n%s\n\n", code)
}

func (c *console) watchICE(ep *icewrap.Endpoint) {
	if !c.verbose {
		return
	}
	_ = ep.OnConnectionStateChange(func(s ice.ConnectionState) {
		c.debugf("ICE %s", s)
	})
}

func (c *console) connected(ep *icewrap.Endpoint) {
	pair, err := ep.SelectedPair()
	if err != nil || pair == nil {
		c.say("Connected.")
		return
	}
	via := "directly"
	if pair.Local.Type() == ice.CandidateTypeRelay || pair.Remote.Type() == ice.CandidateTypeRelay {
		via = "through a TURN relay"
	}
	c.say("Connected %s.", via)
	c.debugf("path %s:%d <-> %s:%d", pair.Local.Address(), pair.Local.Port(), pair.Remote.Address(), pair.Remote.Port())
}

func portsText(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	if len(parts) == 1 {
		return "port " + parts[0]
	}
	return "ports " + strings.Join(parts, ", ")
}

func humanDuration(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return strconv.FormatInt(n, 10) + " " + unit + "s"
	}
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return plural(int64(d/time.Minute), "minute")
	case d >= time.Second && d%time.Second == 0:
		return plural(int64(d/time.Second), "second")
	}
	return d.String()
}
