package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/deploy"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/secrets"
	"github.com/go-freya/freya/services/lcm/internal/store"
	"github.com/go-freya/freya/services/lcm/internal/transfer"
	"github.com/go-freya/freya/services/lcm/internal/webhook"
)

func wantErr(t *testing.T, got error, want *Error) {
	t.Helper()
	var e *Error
	if !errors.As(got, &e) || e != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDomainAndReadError(t *testing.T) {
	wantErr(t, domainError(authz.ErrForbidden), ErrForbidden)
	wantErr(t, domainError(authz.ErrNotFound), ErrNotFound)
	wantErr(t, domainError(store.ErrNotFound), ErrNotFound)
	wantErr(t, domainError(authz.ErrInput), ErrValidation)
	wantErr(t, domainError(csr.ErrTooLarge), ErrBodyTooLarge)
	wantErr(t, domainError(csr.ErrParse), ErrValidation)
	wantErr(t, domainError(csr.ErrWeakKey), ErrValidation)
	wantErr(t, domainError(store.ErrConflict), ErrConflict)

	// above-granter carries a detail.
	var de *DetailError
	if !errors.As(domainError(authz.ErrAboveGranter), &de) || de.Err != ErrForbidden {
		t.Fatal("above-granter detail")
	}
	if de.Error() == "" || de.Unwrap() != ErrForbidden {
		t.Fatal("detail error/unwrap")
	}

	// passthrough of an unmapped error.
	boom := errors.New("boom")
	if domainError(boom) != boom {
		t.Fatal("passthrough")
	}
	// readError masks forbidden as not-found.
	wantErr(t, readError(authz.ErrForbidden), ErrNotFound)
	wantErr(t, readError(store.ErrNotFound), ErrNotFound)
}

func TestServiceErrorMappers(t *testing.T) {
	// issueError.
	var de *DetailError
	if !errors.As(issueError(&issue.ValidationError{Field: "f", Message: "m"}), &de) || de.Err != ErrValidation {
		t.Fatal("issue validation")
	}
	if !errors.As(issueError(&issue.InUseError{What: "certificates", Count: 2}), &de) || de.Err != ErrConflict {
		t.Fatal("issue in-use")
	}
	wantErr(t, issueError(store.ErrNotFound), ErrNotFound)
	wantErr(t, issueReadError(store.ErrNotFound), ErrNotFound)

	// enrollError.
	if !errors.As(enrollError(&enroll.ValidationError{Field: "f", Message: "m"}), &de) || de.Err != ErrValidation {
		t.Fatal("enroll validation")
	}
	wantErr(t, enrollError(&enroll.ConflictError{ID: "x", From: "a", To: "b"}), ErrConflict)
	wantErr(t, enrollError(store.ErrNotFound), ErrNotFound)

	// secretError / webhookError.
	if !errors.As(secretError(&secrets.ValidationError{Field: "f", Message: "m"}), &de) || de.Err != ErrValidation {
		t.Fatal("secret validation")
	}
	wantErr(t, secretError(&secrets.ConflictError{Message: "taken"}), ErrConflict)
	wantErr(t, secretError(store.ErrNotFound), ErrNotFound)
	if !errors.As(webhookError(&webhook.ValidationError{Field: "f", Message: "m"}), &de) || de.Err != ErrValidation {
		t.Fatal("webhook validation")
	}
	wantErr(t, webhookError(&webhook.ConflictError{Message: "taken"}), ErrConflict)
	wantErr(t, webhookError(store.ErrNotFound), ErrNotFound)

	// deployError.
	if !errors.As(deployError(&deploy.ValidationError{Field: "f", Message: "m"}), &de) || de.Err != ErrValidation {
		t.Fatal("deploy validation")
	}
	wantErr(t, deployError(store.ErrNotFound), ErrNotFound)

	// backupError.
	wantErr(t, backupError(transfer.ErrTooLarge), ErrBodyTooLarge)
	wantErr(t, backupError(transfer.ErrInvalid), ErrValidation)
	wantErr(t, backupError(transfer.ErrMode), ErrValidation)
	wantErr(t, backupError(store.ErrNotFound), ErrNotFound)
}

func TestStatusMapping(t *testing.T) {
	if st, _ := Status(ErrForbidden); st != http.StatusForbidden {
		t.Fatal("status *Error")
	}
	if st, _ := Status(store.ErrNotFound); st != http.StatusNotFound {
		t.Fatal("status not found")
	}
	if st, _ := Status(store.ErrConflict); st != http.StatusConflict {
		t.Fatal("status conflict")
	}
	if st, _ := Status(errors.New("x")); st != http.StatusServiceUnavailable {
		t.Fatal("status default")
	}
	if (&Error{Status: 400, Reason: "r"}).Error() != "r" {
		t.Fatal("Error.Error")
	}
}

func TestJSONRawAndAuditView(t *testing.T) {
	if _, ok := jsonRaw([]byte(`{"a":1}`)).(interface{ MarshalJSON() ([]byte, error) }); !ok {
		// json.RawMessage implements Marshaler; a string does not.
		t.Fatal("valid json should be raw")
	}
	if _, ok := jsonRaw([]byte(`not json`)).(string); !ok {
		t.Fatal("invalid json should be a string")
	}
	row := store.AuditRow{TS: time.Unix(1700000000, 0).UTC(), EventType: "e", ActorKind: "user", ActorID: "u",
		SubjectKind: "certificate", SubjectID: "c", Outcome: "ok", SubjectName: "n", Reason: "r",
		CorrelationID: "corr", Details: []byte(`{"k":"v"}`)}
	m := auditView(row)
	if m["event_type"] != "e" || m["subject_name"] != "n" || m["reason"] != "r" || m["correlation_id"] != "corr" || m["details"] == nil {
		t.Fatalf("auditView %+v", m)
	}
}

func TestGrantView(t *testing.T) {
	by := "granter"
	exp := time.Unix(1700001000, 0).UTC()
	g := store.Grant{ID: "g1", ResourceType: "certificate", ResourceID: "c1", SubjectType: "user", SubjectID: "u1",
		Relation: "viewer", GrantedAt: time.Unix(1700000000, 0).UTC(), GrantedBy: &by, ExpiresAt: &exp}
	m := grantView(g)
	if m["id"] != "g1" || m["granted_by"] != "granter" || m["expires_at"] != exp {
		t.Fatalf("grantView %+v", m)
	}
}

func TestExtensionHelpers(t *testing.T) {
	for _, v := range []any{float64(5), int(5), int64(5)} {
		if n, ok := extensionInt(v); !ok || n != 5 {
			t.Fatalf("extensionInt(%T)", v)
		}
	}
	if _, ok := extensionInt("nope"); ok {
		t.Fatal("extensionInt string should fail")
	}
	if !extensionBool(true) || extensionBool("x") {
		t.Fatal("extensionBool")
	}
}

func TestDecodeJSONEdges(t *testing.T) {
	type body struct {
		A int `json:"a"`
	}
	// Unknown field rejected.
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1,"b":2}`))
	if err := DecodeJSON(r, &body{}, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown field: %v", err)
	}
	// Trailing data rejected.
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1}{}`))
	if err := DecodeJSON(r, &body{}, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing data: %v", err)
	}
	// Oversize body rejected.
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"a":123456}`))
	if err := DecodeJSON(r, &body{}, 4); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	// Valid.
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"a":7}`))
	var b body
	if err := DecodeJSON(r, &b, 0); err != nil || b.A != 7 {
		t.Fatalf("valid decode: %v %+v", err, b)
	}
}

func TestCallerRequiresIdentity(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := Caller(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no identity: %v", err)
	}
	if _, err := subjects(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("subjects no identity: %v", err)
	}
	if hasPermission(r, nil, "x") {
		t.Fatal("nil checker => no permission")
	}
	_ = authz.Subjects{}
}
