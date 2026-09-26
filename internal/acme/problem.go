package acme

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"unicode"

	xacme "golang.org/x/crypto/acme"
)

// Bounds on the CA's problem text carried in an error (runes).
const (
	maxProblemRunes = 300
	maxProblemType  = 64
	maxSubproblems  = 3
)

// causeError is a package sentinel with a sanitised, single-line cause:
// "<sentinel>: <cause>". errors.Is matches the sentinel.
type causeError struct {
	sentinel error
	msg      string
}

func (e *causeError) Error() string { return e.sentinel.Error() + ": " + e.msg }
func (e *causeError) Unwrap() error { return e.sentinel }

func withCause(sentinel, cause error) error {
	return &causeError{sentinel: sentinel, msg: describe(cause)}
}

// describe reduces a cause to a short, credential-free description. ACME
// problem documents keep the CA's detail (why the order was refused: an
// invalid or redundant name, a missing TXT record, CAA) and their subproblems,
// sanitised; order/authorization URLs, headers and JWS payloads never appear.
// Transport and DNS-provider errors can echo request bodies, so they keep
// only their class.
func describe(err error) string {
	var oe *xacme.OrderError
	if errors.As(err, &oe) {
		if oe.Problem != nil {
			return describeProblem(oe.Problem)
		}
		return "order " + sanitise(oe.Status, 32)
	}
	var aze *xacme.AuthorizationError
	if errors.As(err, &aze) {
		msg := "authorization for " + sanitise(aze.Identifier, 253) + " failed"
		var parts []string
		for _, e := range aze.Errors {
			if len(parts) == maxSubproblems {
				break
			}
			parts = append(parts, describe(e))
		}
		if len(parts) > 0 {
			msg += ": " + strings.Join(parts, "; ")
		}
		return msg
	}
	var ae *xacme.Error
	if errors.As(err, &ae) {
		return describeProblem(ae)
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "network error contacting directory"
	}
	return "request failed"
}

func describeProblem(e *xacme.Error) string {
	detail := sanitise(e.Detail, maxProblemRunes)
	if detail == "" {
		detail = "server rejected request"
	}
	var subs []string
	for _, sp := range e.Subproblems {
		if len(subs) == maxSubproblems {
			break
		}
		d := sanitise(sp.Detail, maxProblemRunes)
		if d == "" {
			continue
		}
		if sp.Identifier != nil && sp.Identifier.Value != "" {
			d = sanitise(sp.Identifier.Value, 253) + ": " + d
		}
		subs = append(subs, d)
	}
	if len(subs) > 0 {
		detail = truncate(detail+"; "+strings.Join(subs, "; "), maxProblemRunes)
	}
	if t := sanitise(e.ProblemType, maxProblemType); t != "" {
		detail += " (" + t + ")"
	}
	return detail
}

var (
	// credentialPair is "secret=…", "token: …", "api_key=…" and the like.
	credentialPair = regexp.MustCompile(`(?i)\b(secret|token|password|passwd|api[_-]?key|key|authorization|credentials?|hmac|signature)(\s*[:=]\s*)(bearer\s+)?\S+`)
	bearerToken    = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
	// opaqueRun is a long base64/hex-like run (key material, JWS segments).
	opaqueRun = regexp.MustCompile(`[A-Za-z0-9+/_=-]{40,}`)
)

// sanitise makes CA-supplied text safe to show: single line (control
// characters become spaces, whitespace collapses), credential-like values
// redacted, bounded to max runes.
func sanitise(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = credentialPair.ReplaceAllString(s, "$1$2[redacted]")
	s = bearerToken.ReplaceAllString(s, "Bearer [redacted]")
	s = opaqueRun.ReplaceAllString(s, "[redacted]")
	return truncate(s, max)
}

func truncate(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
