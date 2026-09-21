package secrets

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
)

const tenant = "11111111-1111-7111-8111-111111111111"

func newSvc(t *testing.T) (*Service, *memstore.Mem) {
	t.Helper()
	st := memstore.New()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	aw := audit.NewWriter(st, nil)
	t.Cleanup(aw.Close)
	return New(st, env, aw, func() time.Time { return time.Unix(1700000000, 0) }), st
}

func admin() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

func TestCreate_ListGet_NeverExposeValue(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t)
	v, err := s.Create(ctx, admin(), Input{Name: "acme", Kind: KindACMEAccount, Value: sealed.Settings{"account_key": "TOPSECRET"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if v.ID == "" || v.Name != "acme" || v.Kind != KindACMEAccount {
		t.Fatalf("bad view: %+v", v)
	}
	if v.CreatedBy != admin().UserID {
		t.Fatalf("created_by = %q", v.CreatedBy)
	}
	// The value is sealed on the row and never surfaces in the view (SR-001).
	row := st.Secrets[v.ID]
	if len(row.ValueSealed) == 0 {
		t.Fatal("value not sealed")
	}
	if bytesContains(row.ValueSealed, "TOPSECRET") {
		t.Fatal("plaintext secret found in sealed blob")
	}
	got, err := s.Get(ctx, admin(), v.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != v {
		t.Fatalf("get mismatch: %+v vs %+v", got, v)
	}
	list, err := s.List(ctx, admin())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v n=%d", err, len(list))
	}
}

func TestCreate_KindAndNameValidation(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, err := s.Create(ctx, admin(), Input{Name: "x", Kind: "bogus", Value: sealed.Settings{"k": "v"}}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if _, err := s.Create(ctx, admin(), Input{Name: "", Kind: KindACMEAccount, Value: sealed.Settings{"k": "v"}}); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := s.Create(ctx, admin(), Input{Name: "y", Kind: KindDNSCredential}); err == nil {
		t.Fatal("empty value accepted")
	}
	// name uniqueness (case-insensitive)
	if _, err := s.Create(ctx, admin(), Input{Name: "Dup", Kind: KindDNSCredential, Value: sealed.Settings{"token": "a"}}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.Create(ctx, admin(), Input{Name: "dup", Kind: KindDNSCredential, Value: sealed.Settings{"token": "b"}})
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ConflictError, got %v", err)
	}
}

func TestUpdate_KeepsStoredOnMarker(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	v, err := s.Create(ctx, admin(), Input{Name: "dns", Kind: KindDNSCredential, Value: sealed.Settings{"token": "ORIGINAL", "zone": "z1"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Marker keeps the stored token; zone replaced.
	if _, err := s.Update(ctx, admin(), v.ID, Input{Name: "dns2", Value: sealed.Settings{"token": sealed.Marker, "zone": "z2"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	val, err := s.OpenValue(ctx, tenant, v.ID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if val["token"] != "ORIGINAL" {
		t.Fatalf("token not kept on marker: %v", val["token"])
	}
	if val["zone"] != "z2" {
		t.Fatalf("zone not updated: %v", val["zone"])
	}
	got, _ := s.Get(ctx, admin(), v.ID)
	if got.Name != "dns2" {
		t.Fatalf("name not updated: %q", got.Name)
	}
}

func TestRotate_ReplacesValue(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	v, err := s.Create(ctx, admin(), Input{Name: "r", Kind: KindACMEAccount, Value: sealed.Settings{"account_key": "OLD", "extra": "keep?"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Rotate(ctx, admin(), v.ID, sealed.Settings{"account_key": "NEW"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	val, err := s.OpenValue(ctx, tenant, v.ID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if val["account_key"] != "NEW" {
		t.Fatalf("rotate did not replace: %v", val["account_key"])
	}
	if _, ok := val["extra"]; ok {
		t.Fatal("rotate must replace the whole value, extra survived")
	}
}

func TestOpenValue_RoundTrips_AndDelete(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t)
	v, err := s.Create(ctx, admin(), Input{Name: "rt", Kind: KindDNSCredential, Value: sealed.Settings{"token": "abc", "num": float64(3)}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	val, err := s.OpenValue(ctx, tenant, v.ID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if val["token"] != "abc" || val["num"] != float64(3) {
		t.Fatalf("round-trip mismatch: %+v", val)
	}
	if err := s.Delete(ctx, admin(), v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := st.Secrets[v.ID]; ok {
		t.Fatal("secret not deleted")
	}
}

func bytesContains(b []byte, sub string) bool {
	return len(sub) > 0 && indexOf(string(b), sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestUpdate_MissingAndErrorShapes(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	if _, err := s.Update(ctx, admin(), "no-such-id", Input{Name: "n", Value: sealed.Settings{"k": "v"}}); err == nil {
		t.Fatal("update of missing secret should error")
	}
	if _, err := s.Rotate(ctx, admin(), "no-such-id", sealed.Settings{"k": "v"}); err == nil {
		t.Fatal("rotate of missing secret should error")
	}
	if err := s.Delete(ctx, admin(), "no-such-id"); err == nil {
		t.Fatal("delete of missing secret should error")
	}
	ve := &ValidationError{Field: "name", Message: "bad"}
	if ve.Error() != "name: bad" {
		t.Fatalf("ValidationError.Error = %q", ve.Error())
	}
	ce := &ConflictError{Message: "dup"}
	if ce.Error() != "dup" {
		t.Fatalf("ConflictError.Error = %q", ce.Error())
	}
}
