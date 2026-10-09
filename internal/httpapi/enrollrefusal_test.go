package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
)

// Each enrollment refusal answers its own closed reason (never the token): the
// auth verdict on the token is 401, lcm's refusal of the identity is 403, and a
// verifier outage is a retryable 503.
func TestEnrollRefusalReasons(t *testing.T) {
	f := newAPI(t)
	for _, c := range []struct {
		token, spiffeID string
		status          int
		body            string
	}{
		{"enrollment_token_expired", "spiffe://infra.example.org/svc/a", http.StatusUnauthorized, `{"reason":"enrollment_token_expired"}`},
		{"enrollment_token_not_yet_valid", "spiffe://infra.example.org/svc/a", http.StatusUnauthorized, `{"reason":"enrollment_token_not_yet_valid"}`},
		{"enrollment_token_used", "spiffe://infra.example.org/svc/a", http.StatusUnauthorized, `{"reason":"enrollment_token_used"}`},
		{"enrollment_token_invalid", "spiffe://infra.example.org/svc/a", http.StatusUnauthorized, `{"reason":"enrollment_token_invalid"}`},
		{"opaque-refusal", "spiffe://infra.example.org/svc/a", http.StatusUnauthorized, `{"reason":"enrollment_token_invalid"}`},
		{"auth-down", "spiffe://infra.example.org/svc/a", http.StatusServiceUnavailable, `{"reason":"temporarily_unavailable"}`},
		{"grant", "spiffe://infra.example.org/svc/b", http.StatusForbidden, `{"reason":"enrollment_spiffe_id_not_allowed"}`},
		{"grant", "spiffe://example.org/svc/a", http.StatusForbidden, `{"detail":{"expected_trust_domain":"infra.example.org"},"reason":"enrollment_trust_domain_mismatch"}`},
	} {
		w := f.req(t, "POST", Prefix+"/enroll", "", `{"spiffe_id":"`+c.spiffeID+`","enrollment_token":"`+c.token+`"}`)
		if w.Code != c.status || strings.TrimSpace(w.Body.String()) != c.body {
			t.Fatalf("%s %s: %d %s", c.token, c.spiffeID, w.Code, w.Body.String())
		}
	}
}

// FailEnroll (the dedicated enroll listener) answers the same bodies.
func TestFailEnroll(t *testing.T) {
	r := httptest.NewRequest("POST", "https://localhost"+Prefix+"/enroll", nil)
	w := httptest.NewRecorder()
	FailEnroll(w, r, nil, &enroll.RefusalError{Reason: enroll.ReasonTrustDomainMismatch, Detail: map[string]any{"expected_trust_domain": "infra.example.org"}})
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != `{"detail":{"expected_trust_domain":"infra.example.org"},"reason":"enrollment_trust_domain_mismatch"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	FailEnroll(w, r, nil, &enroll.RefusalError{Reason: enroll.ReasonTokenExpired})
	if w.Code != http.StatusUnauthorized || strings.TrimSpace(w.Body.String()) != `{"reason":"enrollment_token_expired"}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
