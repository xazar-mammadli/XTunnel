package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xazar/xtunnel/internal/icewrap"
	"github.com/xazar/xtunnel/internal/tunnel"
)

var defaultSTUN = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// portList implements flag.Value for repeatable --expose flags.
type portList []uint16

func (l *portList) String() string {
	parts := make([]string, len(*l))
	for i, p := range *l {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

func (l *portList) Set(s string) error {
	p, err := parsePort(s)
	if err != nil {
		return err
	}
	*l = append(*l, p)
	return nil
}

// forwardList implements flag.Value for repeatable -L flags.
// Accepted forms:
//
//	-L 8080                  127.0.0.1:8080 -> peer:8080
//	-L 15432:5432            127.0.0.1:15432 -> peer:5432
//	-L 0.0.0.0:8080:80       0.0.0.0:8080 -> peer:80
type forwardList []tunnel.Forward

func (l *forwardList) String() string {
	parts := make([]string, len(*l))
	for i, f := range *l {
		parts[i] = fmt.Sprintf("%s:%d", f.Listen, f.Port)
	}
	return strings.Join(parts, ",")
}

func (l *forwardList) Set(s string) error {
	parts := strings.Split(s, ":")
	var bind, local, remote string
	switch len(parts) {
	case 1:
		bind, local, remote = "127.0.0.1", parts[0], parts[0]
	case 2:
		bind, local, remote = "127.0.0.1", parts[0], parts[1]
	case 3:
		bind, local, remote = parts[0], parts[1], parts[2]
	default:
		return fmt.Errorf("invalid forward spec %q (want [bind:]local:remote or port)", s)
	}
	lp, err := parsePort(local)
	if err != nil {
		return fmt.Errorf("forward spec %q: %w", s, err)
	}
	rp, err := parsePort(remote)
	if err != nil {
		return fmt.Errorf("forward spec %q: %w", s, err)
	}
	*l = append(*l, tunnel.Forward{
		Listen: fmt.Sprintf("%s:%d", bind, lp),
		Port:   rp,
	})
	return nil
}

// stringList implements flag.Value for repeatable string flags (--stun).
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

// turnList implements flag.Value for repeatable --turn url,user,pass flags.
type turnList []icewrap.TURNServer

func (l *turnList) String() string {
	parts := make([]string, len(*l))
	for i, t := range *l {
		parts[i] = t.URL
	}
	return strings.Join(parts, " ")
}

func (l *turnList) Set(s string) error {
	parts := strings.SplitN(s, ",", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid --turn %q (want url,username,password)", s)
	}
	*l = append(*l, icewrap.TURNServer{URL: parts[0], Username: parts[1], Password: parts[2]})
	return nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(n), nil
}
