package signal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const secretDigits = 6

var (
	nameplateRe = regexp.MustCompile(`^[0-9]{1,5}$`)
	codeRe      = regexp.MustCompile(fmt.Sprintf(`^[0-9]{1,5}-[0-9]{%d}$`, secretDigits))
)

func NewNameplate(attempt int) (string, error) {
	span := int64(999)
	if attempt >= 8 {
		span = 99999
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", n.Int64()+1), nil
}

func NewSecret() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", secretDigits, n.Int64()), nil
}

func Nameplate(code string) string {
	code = strings.TrimSpace(code)
	if i := strings.IndexByte(code, '-'); i >= 0 {
		return code[:i]
	}
	return code
}

func ValidNameplate(s string) bool {
	return nameplateRe.MatchString(s)
}

func ValidCode(code string) bool {
	return codeRe.MatchString(strings.TrimSpace(code))
}
