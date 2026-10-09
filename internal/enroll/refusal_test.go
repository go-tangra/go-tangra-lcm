package enroll

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
)

// The verifier's verdict on the token passes through as its reason; a verdict
// without a known reason is opaque; an outage is not a refusal at all.
func TestEnrollTokenRefusalReasons(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		reason string
	}{
		{"expired", &RefusalError{Reason: ReasonTokenExpired}, ReasonTokenExpired},
		{"not yet valid", &RefusalError{Reason: ReasonTokenNotYetValid}, ReasonTokenNotYetValid},
		{"used", fmt.Errorf("wrapped: %w", &RefusalError{Reason: ReasonTokenUsed}), ReasonTokenUsed},
		{"invalid", &RefusalError{Reason: ReasonTokenInvalid}, ReasonTokenInvalid},
		{"plain error", errors.New("token already used"), ReasonTokenInvalid},
		{"non-token reason", &RefusalError{Reason: ReasonSpiffeIDNotAllowed}, ReasonTokenInvalid},
	} {
		f := newFixture(t, Config{AutoApprove: true}, &fakeVerifier{err: c.err})
		_, err := f.svc.Enroll(context.Background(), authz.Subjects{TenantID: "t1"}, EnrollInput{SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "tok"})
		var re *RefusalError
		if !errors.As(err, &re) || re.Reason != c.reason || !re.TokenRefused() || !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}

	f := newFixture(t, Config{AutoApprove: true}, &fakeVerifier{err: fmt.Errorf("%w: auth down", ErrVerifierUnavailable)})
	_, err := f.svc.Enroll(context.Background(), authz.Subjects{TenantID: "t1"}, EnrollInput{SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "tok"})
	var re *RefusalError
	if !errors.Is(err, ErrVerifierUnavailable) || errors.Is(err, ErrForbidden) || errors.As(err, &re) {
		t.Fatalf("outage: %v", err)
	}
}

// An authentic token that does not name the requested id: a foreign trust
// domain names the expected one (a misconfigured workload); a foreign path in
// the right trust domain is simply not allowed. Nothing is issued.
func TestEnrollGrantRefusalReasons(t *testing.T) {
	for _, c := range []struct {
		name   string
		paths  []string
		want   string
		reason string
		detail map[string]any
	}{
		{"wrong trust domain", []string{"spiffe://infra.example.org/svc/a"}, "spiffe://example.org/svc/a",
			ReasonTrustDomainMismatch, map[string]any{"expected_trust_domain": "infra.example.org"}},
		{"several trust domains", []string{"spiffe://a.example.org/x", "spiffe://b.example.org/x", "spiffe://a.example.org/y"}, "spiffe://example.org/x",
			ReasonTrustDomainMismatch, map[string]any{"expected_trust_domains": []string{"a.example.org", "b.example.org"}}},
		{"wrong path", []string{"spiffe://infra.example.org/svc/a", "spiffe://other.example.org/svc/b"}, "spiffe://infra.example.org/svc/b",
			ReasonSpiffeIDNotAllowed, nil},
		{"unparseable grant", []string{"svc/a"}, "spiffe://example.org/svc/a", ReasonSpiffeIDNotAllowed, nil},
	} {
		f := newFixture(t, Config{AutoApprove: true}, &fakeVerifier{grant: EnrollGrant{TenantID: "t1", SpiffePaths: c.paths}})
		_, err := f.svc.Enroll(context.Background(), authz.Subjects{TenantID: "t1"}, EnrollInput{SpiffeID: c.want, EnrollmentToken: "tok"})
		var re *RefusalError
		if !errors.As(err, &re) || re.Reason != c.reason || re.TokenRefused() || !reflect.DeepEqual(re.Detail, c.detail) || !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s: %v %+v", c.name, err, re)
		}
		if re.Error() != "enroll: "+c.reason {
			t.Fatalf("%s: message %q", c.name, re.Error())
		}
		if len(f.mem.Certificates) != 0 {
			t.Fatalf("%s: issued despite refusal", c.name)
		}
	}
}
