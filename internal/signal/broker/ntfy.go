// Package broker implements a signal.Transport over a public generic pub/sub
// service, so two peers can rendezvous for NAT traversal without anyone
// running an xtunnel server. The default service is ntfy (https://ntfy.sh):
// publish is an HTTP POST to a topic, subscribe is a WebSocket stream of that
// topic's messages.
//
// The broker is fully untrusted. Confidentiality and MITM resistance come from
// the PAKE that runs on top (signal.Secure): the broker only ever sees
// ciphertext, a rendezvous topic derived from a high-entropy one-time code, and
// the two peers' IP addresses. The topic is HKDF(code), so only a party that
// already knows the code can even find the rendezvous.
package broker

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// DefaultURL is the public pub/sub service used when none is given.
const DefaultURL = "https://ntfy.sh"

// maxMessage is ntfy's plain-message ceiling; larger or non-UTF-8 bodies get
// turned into attachments, which we must avoid, so we base64 every frame and
// keep it under this.
const maxMessage = 4096

// Transport is a signal.Transport backed by a public ntfy-style broker.
type Transport struct {
	pubURL string // topic we publish to
	subURL string // WebSocket topic we read from
	httpc  *http.Client
	ws     *websocket.Conn
}

// topics derives the two per-direction topics from the pairing code. Each side
// publishes on one and subscribes on the other so it never reads its own
// messages. Both topics carry a shared prefix so they are recognizably one
// rendezvous, and are unguessable without the code.
func topics(code string) (offererPub, answererPub string, err error) {
	key, err := hkdf.Key(sha256.New, []byte(code), nil, "xtunnel/broker/topic", 20)
	if err != nil {
		return "", "", err
	}
	b := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key))
	// ntfy topics must be reasonably short and URL-safe; base32 is both.
	return "xt-" + b + "-o", "xt-" + b + "-a", nil
}

// Dial connects to the broker for one side of a pairing. isHost is the offerer
// (it publishes on the "-o" topic and reads the "-a" topic); the joiner is the
// mirror. baseURL may be empty for DefaultURL.
func Dial(ctx context.Context, baseURL, code string, isHost bool) (*Transport, error) {
	if baseURL == "" {
		baseURL = DefaultURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse broker URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("broker URL must be http(s), got %q", u.Scheme)
	}

	oTopic, aTopic, err := topics(code)
	if err != nil {
		return nil, err
	}
	pubTopic, subTopic := oTopic, aTopic
	if !isHost {
		pubTopic, subTopic = aTopic, oTopic
	}

	httpBase := strings.TrimRight(u.String(), "/")
	wsScheme := "wss"
	if u.Scheme == "http" {
		wsScheme = "ws"
	}
	// since=2m replays the last couple of minutes so a peer that published
	// just before we subscribed is not missed (ntfy delivers only NEW messages
	// by default). Codes are one-time and topics are HKDF(code), so this only
	// ever scopes to the current pairing's traffic — no cross-session replay.
	subURL := fmt.Sprintf("%s://%s/%s/ws?since=2m", wsScheme, u.Host, subTopic)

	t := &Transport{
		pubURL: httpBase + "/" + pubTopic,
		subURL: subURL,
		httpc:  &http.Client{Timeout: 30 * time.Second},
	}

	ws, _, err := websocket.Dial(ctx, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("subscribe to broker: %w", err)
	}
	ws.SetReadLimit(1 << 20)
	t.ws = ws
	return t, nil
}

// Send publishes one signaling frame (base64 to stay UTF-8 and under the
// broker's plain-message limit).
func (t *Transport) Send(ctx context.Context, body []byte) error {
	enc := base64.RawStdEncoding.EncodeToString(body)
	if len(enc) > maxMessage {
		return fmt.Errorf("signaling frame too large for broker: %d > %d bytes", len(enc), maxMessage)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.pubURL, bytes.NewReader([]byte(enc)))
	if err != nil {
		return err
	}
	// Avoid ntfy turning the body into a notification/attachment.
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Priority", "min")
	resp, err := t.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("publish to broker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("broker publish failed: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ntfyEvent is the subset of ntfy's WebSocket JSON we care about.
type ntfyEvent struct {
	Event   string `json:"event"`
	Message string `json:"message"`
}

// Recv returns the next signaling frame from the peer, skipping the broker's
// own control events (open/keepalive).
func (t *Transport) Recv(ctx context.Context) ([]byte, error) {
	for {
		_, data, err := t.ws.Read(ctx)
		if err != nil {
			return nil, err
		}
		var ev ntfyEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			continue // ignore anything that is not a JSON event
		}
		if ev.Event != "message" {
			continue // open, keepalive, poll_request, etc.
		}
		body, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(ev.Message))
		if err != nil {
			continue // not one of our frames
		}
		return body, nil
	}
}

// Close tears down the subscription WebSocket.
func (t *Transport) Close() error {
	if t.ws != nil {
		return t.ws.Close(websocket.StatusNormalClosure, "bye")
	}
	return nil
}
