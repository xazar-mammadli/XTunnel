package signal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
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

var codeRe = regexp.MustCompile(`^[0-9]{1,2}-[a-z]+-[a-z]+$`)

// NewRoomCode generates a fresh "N-word-word" room code.
func NewRoomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(98))
	if err != nil {
		return "", err
	}
	w1, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeWords))))
	if err != nil {
		return "", err
	}
	w2, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeWords))))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s-%s", n.Int64()+2, codeWords[w1.Int64()], codeWords[w2.Int64()]), nil
}

// ValidRoomCode is a cheap syntactic check used before registry lookups.
func ValidRoomCode(code string) bool {
	return len(code) <= 32 && codeRe.MatchString(code)
}
