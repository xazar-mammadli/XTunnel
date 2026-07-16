package signal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// codeWords is a 128-entry list of short, phonetically distinct English
// words. A code "N-word-word" carries log2(98*128*128) ~= 20.6 bits — in the
// same class as magic-wormhole's default (16 bits). Combined with one-time
// codes, a 10-minute TTL, PAKE (one online guess per join) and per-IP rate
// limiting, online guessing is impractical.
var codeWords = []string{
	"acid", "acorn", "amber", "anchor", "apple", "arrow", "atlas", "atom",
	"badge", "bagel", "bamboo", "banjo", "basil", "beach", "berry", "bison",
	"blade", "blossom", "bolt", "bridge", "bronze", "brush", "bubble", "butter",
	"cabin", "cactus", "camel", "candle", "canoe", "canyon", "carbon", "castle",
	"cedar", "cello", "cherry", "chess", "cliff", "cloud", "clover", "cobra",
	"coconut", "comet", "copper", "coral", "cotton", "crane", "crystal", "cypress",
	"daisy", "delta", "denim", "desert", "diamond", "dolphin", "domino", "dragon",
	"eagle", "echo", "ember", "engine", "falcon", "fern", "flint", "forest",
	"fossil", "fox", "galaxy", "garden", "garlic", "geyser", "ginger", "glacier",
	"granite", "grape", "hammer", "harbor", "hawk", "hazel", "heron", "honey",
	"iceberg", "iris", "ivory", "jade", "jaguar", "jasmine", "jungle", "juniper",
	"kayak", "kettle", "lagoon", "lantern", "lemon", "lily", "lobster", "lotus",
	"magnet", "mango", "maple", "marble", "meadow", "meteor", "mint", "molar",
	"nebula", "nickel", "nutmeg", "oasis", "olive", "onyx", "orchid", "otter",
	"panda", "peach", "pearl", "pepper", "piano", "pigeon", "pine", "planet",
	"plum", "prism", "quartz", "raven", "reef", "river", "salmon", "zebra",
}

var (
	// nameplateRe matches the server-assigned routing id (not secret).
	nameplateRe = regexp.MustCompile(`^[0-9]{1,5}$`)
	// codeRe matches a full pairing code: nameplate + secret words.
	codeRe = regexp.MustCompile(`^[0-9]{1,5}(-[a-z]+){2,}$`)
)

// secretWordCount is how many secret words the client mixes into the code.
// Three words over a 128-word list is ~21 bits — comparable to magic-wormhole
// and, combined with a one-time code + PAKE (one online guess) + rate limiting,
// impractical to guess online.
const secretWordCount = 3

// NewNameplate generates a short server-side routing id. It is NOT secret: the
// server assigns it and uses it only to pair the two peers. The PAKE password
// is the full code, whose secret words are generated client-side and never
// reach the server.
func NewNameplate() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", n.Int64()+10000), nil
}

// NewSecretWords generates the client-side secret portion of a pairing code.
// This is the entropy the server must not know: it is the PAKE password
// material, so a malicious server cannot derive the session key and MITM.
func NewSecretWords() (string, error) {
	words := make([]string, secretWordCount)
	for i := range words {
		w, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeWords))))
		if err != nil {
			return "", err
		}
		words[i] = codeWords[w.Int64()]
	}
	return strings.Join(words, "-"), nil
}

// Nameplate extracts the routing id (the part before the first "-") from a
// full pairing code. The remaining secret words never leave the client.
func Nameplate(code string) string {
	code = strings.TrimSpace(code)
	if i := strings.IndexByte(code, '-'); i >= 0 {
		return code[:i]
	}
	return code
}

// ValidNameplate checks the server-side routing id.
func ValidNameplate(s string) bool {
	return len(s) <= 8 && nameplateRe.MatchString(s)
}

// ValidCode checks the full client-facing pairing code (nameplate + words).
func ValidCode(code string) bool {
	code = strings.TrimSpace(code)
	return len(code) <= 64 && codeRe.MatchString(code)
}

// pairingWordCount is how many words a broker-mode pairing code carries.
// Broker mode has NO server-side room burning or rate limiting (the public
// broker is a dumb relay), so the code alone must resist online guessing and
// topic collision. Six words over the 128-word list is ~42 bits — the topic
// (HKDF of the code) is unguessable and collisions between concurrent
// pairings are negligible.
const pairingWordCount = 6

// pairingRe matches a broker-mode pairing code: only words (no nameplate).
var pairingRe = regexp.MustCompile(`^[a-z]+(-[a-z]+){3,}$`)

// NewPairingCode generates a high-entropy word-only code for broker mode. The
// whole code is the PAKE password and, via HKDF, the rendezvous topic; there
// is no server component, so it is fully client-generated and one-time.
func NewPairingCode() (string, error) {
	words := make([]string, pairingWordCount)
	for i := range words {
		w, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeWords))))
		if err != nil {
			return "", err
		}
		words[i] = codeWords[w.Int64()]
	}
	return strings.Join(words, "-"), nil
}

// ValidPairingCode checks a broker-mode (word-only) pairing code.
func ValidPairingCode(code string) bool {
	code = strings.TrimSpace(code)
	return len(code) <= 96 && pairingRe.MatchString(code)
}
