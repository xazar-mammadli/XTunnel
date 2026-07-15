// Package signal implements xtunnel's rendezvous signaling: a WebSocket
// mailbox protocol (shared by client and xtunneld server), a PAKE handshake
// keyed by the room code, and an AEAD-encrypted framing on top so the server
// relays only ciphertext.
package signal

// Envelope is the plaintext mailbox protocol between a peer and xtunneld.
// The server never sees inside Body: it is PAKE/AEAD protected.
type Envelope struct {
	// Type is one of:
	//   client -> server: "create", "join", "msg"
	//   server -> client: "created", "joined", "peer", "msg", "peer-left", "error"
	Type string `json:"type"`
	Room string `json:"room,omitempty"`
	Body []byte `json:"body,omitempty"`
	Err  string `json:"error,omitempty"`
	// TURN carries ephemeral relay credentials issued by the server on
	// "created"/"joined". Not secret from the server (it runs the relay);
	// the mailbox connection's TLS protects them on the wire.
	TURN []TURNCred `json:"turn,omitempty"`
}

// Signaling message types carried inside encrypted frames.
const (
	MsgHello = "hello" // first frame in each direction; doubles as PAKE key confirmation
	MsgCand  = "cand"  // one trickled ICE candidate
	MsgTURN  = "turn"  // ephemeral TURN credentials issued by the host side
)

// Hello is each side's opening signaling frame.
type Hello struct {
	// FP is the hex SHA-256 fingerprint of this peer's session TLS cert.
	FP string `json:"fp"`
	// Ufrag/Pwd are this peer's local ICE credentials.
	Ufrag string `json:"ufrag"`
	Pwd   string `json:"pwd"`
}

// Cand carries one ICE candidate in SDP attribute form.
type Cand struct {
	C string `json:"c"`
	// End marks the end of trickling (no candidate attached).
	End bool `json:"end,omitempty"`
}

// TURNCred delivers ephemeral relay credentials (filled in by xtunneld).
type TURNCred struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}
