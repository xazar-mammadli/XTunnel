package signal

type Envelope struct {
	Type      string     `json:"type"`
	Room      string     `json:"room,omitempty"`
	Body      []byte     `json:"body,omitempty"`
	Err       string     `json:"error,omitempty"`
	TURN      []TURNCred `json:"turn,omitempty"`
	Reconnect bool       `json:"reconnect,omitempty"`
}

const MsgHello = "hello"

type Hello struct {
	FP    string   `json:"fp"`
	Ufrag string   `json:"ufrag"`
	Pwd   string   `json:"pwd"`
	Cands []string `json:"cands,omitempty"`
	Rid   string   `json:"rid,omitempty"`
	Reply bool     `json:"reply,omitempty"`
}

type TURNCred struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}
