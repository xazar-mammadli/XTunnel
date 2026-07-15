package blob

import (
	"net/netip"
	"strings"
	"testing"
)

func sampleBlob() *Blob {
	var b Blob
	b.IsAnswer = true
	for i := range b.Seed {
		b.Seed[i] = byte(i)
	}
	for i := range b.Fingerprint {
		b.Fingerprint[i] = byte(255 - i)
	}
	b.Candidates = []Candidate{
		{Addr: netip.MustParseAddr("192.168.1.10"), Port: 54321},
		{Addr: netip.MustParseAddr("85.132.44.7"), Port: 61234},
		{Addr: netip.MustParseAddr("2001:db8::1"), Port: 443},
	}
	return &b
}

func TestRoundTrip(t *testing.T) {
	orig := sampleBlob()
	enc := orig.Encode()
	t.Logf("sample blob (%d chars): %s", len(enc), enc)

	got, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.IsAnswer != orig.IsAnswer || got.Seed != orig.Seed || got.Fingerprint != orig.Fingerprint {
		t.Fatal("header fields mismatch after round trip")
	}
	if len(got.Candidates) != len(orig.Candidates) {
		t.Fatalf("candidate count: got %d want %d", len(got.Candidates), len(orig.Candidates))
	}
	for i := range got.Candidates {
		if got.Candidates[i] != orig.Candidates[i] {
			t.Errorf("candidate %d: got %v want %v", i, got.Candidates[i], orig.Candidates[i])
		}
	}
}

func TestBlobSize(t *testing.T) {
	// Typical dual-stack machine: 2 host IPv4 + 1 srflx IPv4 + 1 IPv6.
	b := &Blob{
		Candidates: []Candidate{
			{Addr: netip.MustParseAddr("192.168.1.10"), Port: 54321},
			{Addr: netip.MustParseAddr("10.8.0.3"), Port: 54321},
			{Addr: netip.MustParseAddr("85.132.44.7"), Port: 61234},
			{Addr: netip.MustParseAddr("2001:db8:85a3::8a2e:370:7334"), Port: 54321},
		},
	}
	enc := b.Encode()
	t.Logf("typical blob: %d chars", len(enc))
	if len(enc) > 140 {
		t.Errorf("typical blob too large: %d chars (target <=140)", len(enc))
	}
}

func TestDeriveICECredentialsDeterministicAndValid(t *testing.T) {
	var seed [16]byte
	copy(seed[:], "0123456789abcdef")
	u1, p1, err := DeriveICECredentials(seed)
	if err != nil {
		t.Fatal(err)
	}
	u2, p2, err := DeriveICECredentials(seed)
	if err != nil {
		t.Fatal(err)
	}
	if u1 != u2 || p1 != p2 {
		t.Fatal("credentials not deterministic")
	}
	if len(u1) != 16 || len(p1) != 24 {
		t.Fatalf("unexpected lengths: ufrag %d pwd %d", len(u1), len(p1))
	}
	const iceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, s := range []string{u1, p1} {
		for _, r := range s {
			if !strings.ContainsRune(iceChars, r) {
				t.Fatalf("invalid ice-char %q in %q", r, s)
			}
		}
	}

	var other [16]byte
	other[0] = 1
	u3, _, err := DeriveICECredentials(other)
	if err != nil {
		t.Fatal(err)
	}
	if u3 == u1 {
		t.Fatal("different seeds produced identical ufrag")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"hello",
		"xt1_",
		"xt1_!!!!",
		"xt1_AAAA",                        // too short
		"xt2_" + sampleBlob().Encode()[4:], // wrong prefix
	}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q) unexpectedly succeeded", c)
		}
	}
	// Wrong version nibble.
	b := sampleBlob().Encode()
	raw := []byte(b)
	if _, err := Decode(string(raw)); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(sampleBlob().Encode())
	f.Add("xt1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Decode(s)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode to an equivalent blob.
		b2, err := Decode(b.Encode())
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if b2.Seed != b.Seed || b2.Fingerprint != b.Fingerprint || len(b2.Candidates) != len(b.Candidates) {
			t.Fatal("round trip not stable")
		}
	})
}
