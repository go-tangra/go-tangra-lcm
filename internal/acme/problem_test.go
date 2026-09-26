package acme

// ACME problem details (what the CA says is wrong with the order) reach the
// caller single-line, bounded and with anything credential-like redacted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"
)

const redundant = `Domain name "test.server-lab.eu" is redundant with a wildcard domain in the same request`

func TestWrapKeepsProblemDetail(t *testing.T) {
	err := wrap(context.Background(), ErrOrder, &xacme.Error{ProblemType: "urn:ietf:params:acme:error:malformed", Detail: redundant})
	want := `acme: order failed: ` + redundant + ` (urn:ietf:params:acme:error:malformed)`
	if err.Error() != want || !errors.Is(err, ErrOrder) {
		t.Fatalf("got %q, want %q", err, want)
	}
	// Without a detail the problem type still reads.
	err = wrap(context.Background(), ErrChallenge, &xacme.Error{ProblemType: "urn:ietf:params:acme:error:unauthorized"})
	if err.Error() != "acme: dns-01 challenge failed: server rejected request (urn:ietf:params:acme:error:unauthorized)" {
		t.Fatalf("no detail: %q", err)
	}
	// Non-ACME causes keep their terse class.
	if err := wrap(context.Background(), ErrOrder, errors.New("dial secret=abc")); err.Error() != "acme: order failed: request failed" {
		t.Fatalf("generic: %q", err)
	}
}

func TestProblemSubproblemsOrderAndAuthorizationErrors(t *testing.T) {
	sub := &xacme.Error{
		ProblemType: "urn:ietf:params:acme:error:rejectedIdentifier",
		Detail:      "Error creating new order :: Cannot issue for \"*.server.-lab.eu\": Domain name contains an invalid character",
		Subproblems: []xacme.Subproblem{{
			Type: "urn:ietf:params:acme:error:rejectedIdentifier", Detail: "Domain name contains an invalid character",
			Identifier: &xacme.AuthzID{Type: "dns", Value: "*.server.-lab.eu"},
		}},
	}
	m := describe(sub)
	if !strings.Contains(m, `Cannot issue for "*.server.-lab.eu"`) || !strings.Contains(m, "*.server.-lab.eu: Domain name contains an invalid character") || !strings.Contains(m, "rejectedIdentifier") {
		t.Fatalf("subproblems: %q", m)
	}

	oe := &xacme.OrderError{OrderURL: "https://acme.example/order/secret-path", Status: "invalid", Problem: &xacme.Error{ProblemType: "urn:ietf:params:acme:error:caa", Detail: "CAA record forbids issuance"}}
	if m := describe(fmt.Errorf("wait: %w", oe)); !strings.Contains(m, "CAA record forbids issuance") || strings.Contains(m, "secret-path") {
		t.Fatalf("order error: %q", m)
	}
	if m := describe(&xacme.OrderError{OrderURL: "https://acme.example/order/1", Status: "invalid"}); m != "order invalid" {
		t.Fatalf("order error without problem: %q", m)
	}

	ae := &xacme.AuthorizationError{URI: "https://acme.example/authz/secret", Identifier: "www.example.org", Errors: []error{
		&xacme.Error{ProblemType: "urn:ietf:params:acme:error:dns", Detail: "No TXT record found at _acme-challenge.www.example.org"},
	}}
	if m := describe(ae); !strings.Contains(m, "www.example.org") || !strings.Contains(m, "No TXT record found") || strings.Contains(m, "authz/secret") {
		t.Fatalf("authorization error: %q", m)
	}
}

func TestProblemDetailSanitised(t *testing.T) {
	long := strings.Repeat("word ", 200)
	m := describe(&xacme.Error{ProblemType: "urn:ietf:params:acme:error:malformed",
		Detail: "bad\nrequest\tsecret=abc token: xyz Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln api_key=k1 " +
			"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ " + long})
	for _, leak := range []string{"abc", "xyz", "eyJhbGciOiJFUzI1NiJ9", "k1", "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ", "\n", "\t"} {
		if strings.Contains(m, leak) {
			t.Fatalf("detail leaked %q: %q", leak, m)
		}
	}
	if !strings.HasPrefix(m, "bad request") || len([]rune(m)) > maxProblemRunes+80 {
		t.Fatalf("detail not single-line/bounded (%d): %q", len(m), m)
	}
}

// End to end: the CA's refusal of the order reaches the caller.
func TestObtainOrderRejectionCarriesDetail(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	ca.override["/new-order"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n-reject")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:malformed", "detail": redundant})
	}
	csr := makeCSR(t, []string{"*.server-lab.eu", "test.server-lab.eu"})
	_, err := c.Obtain(context.Background(), csr, []string{"*.server-lab.eu", "test.server-lab.eu"})
	if !errors.Is(err, ErrOrder) || !strings.Contains(err.Error(), redundant) || strings.Contains(err.Error(), "\n") {
		t.Fatalf("got %v", err)
	}
}
