package taskexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
	schedulerv1 "github.com/go-tangra/go-tangra-scheduler/sdk/v4/api/proto/scheduler/v1"
	sdk "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
)

var now = time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)

// sent is one SendKey call as the fake saw it.
type sent struct {
	tenant, key, recipient, correlation string
	vars                                map[string]string
}

// fakeNotify records calls; answer decides the outcome per recipient.
type fakeNotify struct {
	mu     sync.Mutex
	calls  []sent
	answer func(recipient string) (notifyclient.Result, error)
}

func (f *fakeNotify) SendKey(_ context.Context, tenantID, key, recipient string, vars map[string]string, correlationID string) (notifyclient.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, sent{tenantID, key, recipient, correlationID, vars})
	f.mu.Unlock()
	if f.answer == nil {
		return notifyclient.Result{Sent: true, LogID: "log"}, nil
	}
	return f.answer(recipient)
}

type fixture struct {
	mem    *memstore.Mem
	notify *fakeNotify
	h      *Expiring
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	mem := memstore.New()
	mem.Issuers["iss-a"] = store.Issuer{ID: "iss-a", TenantID: tenantA, Name: "Internal Root"}
	mem.Issuers["iss-b"] = store.Issuer{ID: "iss-b", TenantID: tenantB, Name: "Other Root"}
	n := &fakeNotify{}
	return &fixture{mem: mem, notify: n, h: &Expiring{Repo: mem, Notify: n, Now: func() time.Time { return now }}}
}

func (f *fixture) cert(id, tenant, issuer, subject, sans string, in time.Duration, autoRenew bool) {
	f.mem.Certificates[id] = store.IssuedCertificate{
		ID: id, TenantID: tenant, IssuerID: issuer, Subject: subject, SANs: []byte(sans),
		NotAfter: now.Add(in), Status: "active", AutoRenew: autoRenew,
		CertPEM: "-----BEGIN CERTIFICATE-----SECRETPEM", KeySealed: []byte("sealed"),
	}
}

func req(tenant, payload string) sdk.Request {
	return sdk.Request{ExecutionID: "exec-1", TaskID: "task-1", Type: TypeCheckExpiring, TenantID: tenant, Payload: json.RawMessage(payload)}
}

func TestDescriptor(t *testing.T) {
	ds := Descriptors()
	if len(ds) != 1 {
		t.Fatalf("descriptors = %+v", ds)
	}
	d := ds[0]
	if d.Type != "lcm:check-expiring-certificates" || d.DisplayName != "Notify expiring certificates" || d.DefaultCron != "0 8 * * *" ||
		d.DefaultMaxRetry != 1 || d.Platform || !strings.Contains(d.Description, "recipients") {
		t.Fatalf("descriptor = %+v", d)
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(d.PayloadSchema), &schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	want := map[string]any{
		"type":                 "object",
		"required":             []any{"recipients"},
		"additionalProperties": false,
	}
	for k, v := range want {
		if !reflect.DeepEqual(schema[k], v) {
			t.Fatalf("schema[%s] = %v", k, schema[k])
		}
	}
	props := schema["properties"].(map[string]any)
	days := props["daysBeforeExpiry"].(map[string]any)
	if days["type"] != "integer" || days["minimum"] != 1.0 || days["maximum"] != 365.0 || days["default"] != 7.0 || days["description"] == "" {
		t.Fatalf("daysBeforeExpiry = %v", days)
	}
	rec := props["recipients"].(map[string]any)
	items := rec["items"].(map[string]any)
	if rec["type"] != "array" || rec["minItems"] != 1.0 || rec["maxItems"] != 20.0 || items["type"] != "string" || items["format"] != "email" || rec["description"] == "" {
		t.Fatalf("recipients = %v", rec)
	}
	if len(props) != 2 {
		t.Fatalf("properties = %v", props)
	}

	h := Handlers(&Expiring{})
	if len(h) != 1 || h[TypeCheckExpiring] == nil {
		t.Fatalf("handlers = %v", h)
	}
}

func TestPayloadValidation(t *testing.T) {
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf(`"u%d@example.org"`, i)
	}
	cases := map[string]string{
		"missing recipients": `{}`,
		"empty recipients":   `{"recipients":[]}`,
		"too many":           `{"recipients":[` + strings.Join(many, ",") + `]}`,
		"invalid address":    `{"recipients":["not-an-address"]}`,
		"display name form":  `{"recipients":["Admin <a@example.org>"]}`,
		"header injection":   `{"recipients":["a@example.org\r\nBcc: x@evil.test"]}`,
		"newline":            `{"recipients":["a@example.org\n"]}`,
		"empty address":      `{"recipients":[""]}`,
		"days too low":       `{"daysBeforeExpiry":-1,"recipients":["a@example.org"]}`,
		"days too high":      `{"daysBeforeExpiry":366,"recipients":["a@example.org"]}`,
		"days wrong type":    `{"daysBeforeExpiry":"7","recipients":["a@example.org"]}`,
		"unknown field":      `{"recipients":["a@example.org"],"extra":1}`,
		"trailing data":      `{"recipients":["a@example.org"]} {}`,
	}
	for name, payload := range cases {
		f := newFixture(t)
		f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
		res := f.h.Handle(context.Background(), req(tenantA, payload))
		if res.Success || !res.Permanent {
			t.Errorf("%s: result = %+v", name, res)
		}
		if strings.Contains(res.Message, "evil.test") || strings.Contains(res.Message, "a@example.org") {
			t.Errorf("%s: message echoes an address: %q", name, res.Message)
		}
		if len(f.notify.calls) != 0 {
			t.Errorf("%s: sent %d notifications", name, len(f.notify.calls))
		}
	}
}

func TestNothingExpiring(t *testing.T) {
	for payload, days := range map[string]int{
		`{"recipients":["a@example.org"]}`:                        7,
		`{"daysBeforeExpiry":0,"recipients":["a@example.org"]}`:   7,
		`{"daysBeforeExpiry":1,"recipients":["a@example.org"]}`:   1,
		`{"daysBeforeExpiry":365,"recipients":["a@example.org"]}`: 365,
	} {
		f := newFixture(t)
		// Outside every horizon (and in another tenant within it).
		f.cert("far", tenantA, "iss-a", "CN=far", `[]`, 400*24*time.Hour, false)
		f.cert("other", tenantB, "iss-b", "CN=other", `[]`, time.Hour, false)
		res := f.h.Handle(context.Background(), req(tenantA, payload))
		want := fmt.Sprintf("No certificates expiring within %d days", days)
		if !res.Success || res.Message != want || len(f.notify.calls) != 0 {
			t.Fatalf("%s: result = %+v calls=%d", payload, res, len(f.notify.calls))
		}
	}
}

func TestHorizonUsesDays(t *testing.T) {
	f := newFixture(t)
	f.cert("in", tenantA, "iss-a", "CN=in", `[]`, 2*24*time.Hour, false)
	f.cert("out", tenantA, "iss-a", "CN=out", `[]`, 4*24*time.Hour, false)
	res := f.h.Handle(context.Background(), req(tenantA, `{"daysBeforeExpiry":3,"recipients":["a@example.org"]}`))
	if !res.Success || !strings.HasPrefix(res.Message, "Found 1 certificate(s) expiring within 3 days") {
		t.Fatalf("result = %+v", res)
	}
}

func TestDigestSentPerRecipient(t *testing.T) {
	f := newFixture(t)
	f.cert("c2", tenantA, "iss-a", "CN=api.example.org,O=Acme", `["api.example.org","api2.example.org"]`, 3*24*time.Hour+time.Hour, true)
	f.cert("c1", tenantA, "iss-a", "web.example.org", `["web.example.org"]`, 2*time.Hour, false)
	f.cert("c3", tenantA, "gone", "", `not json`, 5*24*time.Hour, false)
	f.mem.Certificates["c3"] = func() store.IssuedCertificate {
		c := f.mem.Certificates["c3"]
		c.SpiffeID = "spiffe://example.org/w"
		return c
	}()
	f.cert("c4", tenantA, "iss-a", "", `[]`, 6*24*time.Hour, false)
	f.cert("c5", tenantA, "iss-a", "CN=evil\r\nBcc: x", `["a\nb"]`, 6*24*time.Hour+time.Minute, false)
	f.cert("foreign", tenantB, "iss-b", "CN=foreign.example.org", `[]`, time.Hour, false)

	res := f.h.Handle(context.Background(), req(tenantA, `{"recipients":["ops@example.org","sec@example.org","ops@example.org"]}`))
	if !res.Success || res.Message != "Found 5 certificate(s) expiring within 7 days; notified 2 recipient(s)" {
		t.Fatalf("result = %+v", res)
	}
	data, ok := res.Data.(map[string]any)
	if !ok || data["count"] != 5 || data["notified"] != 2 || !reflect.DeepEqual(data["certificate_ids"], []string{"c1", "c2", "c3", "c4", "c5"}) {
		t.Fatalf("data = %#v", res.Data)
	}
	if len(f.notify.calls) != 2 {
		t.Fatalf("calls = %d", len(f.notify.calls))
	}
	for i, rcpt := range []string{"ops@example.org", "sec@example.org"} {
		c := f.notify.calls[i]
		if c.tenant != tenantA || c.key != "lcm.certificates_expiring" || c.recipient != rcpt || c.correlation != "exec-1" {
			t.Fatalf("call %d = %+v", i, c)
		}
		if c.vars["days"] != "7" || c.vars["count"] != "5" || len(c.vars) != 3 {
			t.Fatalf("vars = %v", c.vars)
		}
	}
	lines := strings.Split(f.notify.calls[0].vars["certificates"], "\n")
	want := []string{
		"- web.example.org (web.example.org) — issuer Internal Root — expires 2026-09-28T10:00:00Z (1 day(s)) — auto-renew off",
		"- api.example.org (api.example.org, api2.example.org) — issuer Internal Root — expires 2026-10-01T09:00:00Z (4 day(s)) — auto-renew on",
		"- spiffe://example.org/w — issuer unknown — expires 2026-10-03T08:00:00Z (5 day(s)) — auto-renew off",
		"- c4 — issuer Internal Root — expires 2026-10-04T08:00:00Z (6 day(s)) — auto-renew off",
		"- evil  Bcc: x (a b) — issuer Internal Root — expires 2026-10-04T08:01:00Z (7 day(s)) — auto-renew off",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("certificates =\n%s", strings.Join(lines, "\n"))
	}
	for _, c := range f.notify.calls {
		for _, v := range c.vars {
			if strings.Contains(v, "SECRETPEM") || strings.Contains(v, "foreign") {
				t.Fatalf("digest leaks %q", v)
			}
		}
	}
}

func TestDigestTruncatedAtLimit(t *testing.T) {
	f := newFixture(t)
	f.h.Limit = 2
	for i := range 3 {
		f.cert(fmt.Sprintf("c%d", i), tenantA, "iss-a", "CN=x", `[]`, time.Duration(i+1)*time.Hour, false)
	}
	res := f.h.Handle(context.Background(), req(tenantA, `{"recipients":["a@example.org"]}`))
	if !res.Success || !strings.HasPrefix(res.Message, "Found 2 certificate(s)") {
		t.Fatalf("result = %+v", res)
	}
	if !strings.HasSuffix(f.notify.calls[0].vars["certificates"], "(list limited to the first 2 certificates)") {
		t.Fatalf("certificates = %q", f.notify.calls[0].vars["certificates"])
	}
	if (&Expiring{}).limit() != DefaultLimit {
		t.Fatal("default limit")
	}
}

func TestNotificationOutcomes(t *testing.T) {
	payload := `{"recipients":["a@example.org","b@example.org"]}`
	cases := []struct {
		name      string
		answer    func(string) (notifyclient.Result, error)
		success   bool
		permanent bool
		msg       string
		calls     int
	}{
		{
			name: "retryable",
			answer: func(r string) (notifyclient.Result, error) {
				if r == "b@example.org" {
					return notifyclient.Result{Retryable: true, Reason: "Unavailable"}, nil
				}
				return notifyclient.Result{Sent: true}, nil
			},
			msg: "Found 1 certificate(s) expiring within 7 days; notified 1 of 2 recipient(s), 1 to retry", calls: 2,
		},
		{
			name: "delivery failed permanently",
			answer: func(string) (notifyclient.Result, error) {
				return notifyclient.Result{Reason: "mailbox b@example.org rejected"}, nil
			},
			permanent: true, msg: "Found 1 certificate(s) expiring within 7 days; notified 0 of 2 recipient(s), 2 delivery failure(s)", calls: 2,
		},
		{
			name: "refused by notification",
			answer: func(string) (notifyclient.Result, error) {
				return notifyclient.Result{}, status.Error(codes.FailedPrecondition, "email_not_configured for a@example.org")
			},
			permanent: true, msg: "notification refused the digest: FailedPrecondition", calls: 1,
		},
		{
			name: "unknown template",
			answer: func(string) (notifyclient.Result, error) {
				return notifyclient.Result{}, status.Error(codes.NotFound, "unknown key")
			},
			permanent: true, msg: "notification refused the digest: NotFound", calls: 1,
		},
		{
			name: "plain error",
			answer: func(string) (notifyclient.Result, error) {
				return notifyclient.Result{}, errors.New("dial a@example.org failed")
			},
			permanent: true, msg: "notification refused the digest: Unknown", calls: 1,
		},
	}
	for _, tc := range cases {
		f := newFixture(t)
		f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
		f.notify.answer = tc.answer
		var logs bytes.Buffer
		f.h.Log = slog.New(slog.NewTextHandler(&logs, nil))
		res := f.h.Handle(context.Background(), req(tenantA, payload))
		if strings.Contains(logs.String(), "@") {
			t.Errorf("%s: log leaks an address: %s", tc.name, logs.String())
		}
		if res.Success != tc.success || res.Permanent != tc.permanent || res.Message != tc.msg || len(f.notify.calls) != tc.calls {
			t.Errorf("%s: result = %+v calls=%d", tc.name, res, len(f.notify.calls))
		}
		if strings.Contains(res.Message, "@") {
			t.Errorf("%s: message leaks an address: %q", tc.name, res.Message)
		}
	}
}

func TestRepositoryFailuresRetry(t *testing.T) {
	for _, op := range []string{"ExpiringCertificates", "IssuersByIDs"} {
		f := newFixture(t)
		f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
		f.mem.FailOn(op, errors.New("db down"))
		var logs bytes.Buffer
		f.h.Log = slog.New(slog.NewTextHandler(&logs, nil))
		res := f.h.Handle(context.Background(), req(tenantA, `{"recipients":["a@example.org"]}`))
		if res.Success || res.Permanent || strings.Contains(res.Message, "db down") || len(f.notify.calls) != 0 {
			t.Fatalf("%s: result = %+v", op, res)
		}
		if !strings.Contains(logs.String(), "db down") || strings.Contains(logs.String(), "@") {
			t.Fatalf("%s: log = %s", op, logs.String())
		}
	}
}

func TestCancelledContextRetries(t *testing.T) {
	f := newFixture(t)
	f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
	ctx, cancel := context.WithCancel(context.Background())
	f.notify.answer = func(string) (notifyclient.Result, error) { cancel(); return notifyclient.Result{Sent: true}, nil }
	res := f.h.Handle(ctx, req(tenantA, `{"recipients":["a@example.org","b@example.org"]}`))
	if res.Success || res.Permanent || len(f.notify.calls) != 1 || !strings.Contains(res.Message, "1 to retry") {
		t.Fatalf("result = %+v calls=%d", res, len(f.notify.calls))
	}
}

func TestMisconfigured(t *testing.T) {
	f := newFixture(t)
	f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
	f.h.Notify = nil
	res := f.h.Handle(context.Background(), req(tenantA, `{"recipients":["a@example.org"]}`))
	if res.Success || !res.Permanent {
		t.Fatalf("no notifier: %+v", res)
	}
	// A request without a tenant never reaches the repository.
	f = newFixture(t)
	res = f.h.Handle(context.Background(), req("", `{"recipients":["a@example.org"]}`))
	if res.Success || !res.Permanent {
		t.Fatalf("no tenant: %+v", res)
	}
	// Default clock.
	if (&Expiring{}).now().IsZero() {
		t.Fatal("default clock")
	}
}

// TestThroughExecutorServer runs the handler behind the SDK server as lcm
// wires it: the scheduler peer, the request tenant and the payload reach it.
func TestThroughExecutorServer(t *testing.T) {
	f := newFixture(t)
	f.cert("c1", tenantA, "iss-a", "CN=a", `[]`, time.Hour, false)
	srv := sdk.NewServer(Handlers(f.h), sdk.Options{Caller: func(context.Context) (string, bool) { return "scheduler", true }})
	res, err := srv.ExecuteTask(context.Background(), &schedulerv1.ExecuteTaskRequest{
		ExecutionId: "exec-9", TaskType: TypeCheckExpiring, TenantId: tenantA, Payload: []byte(`{"recipients":["a@example.org"]}`),
	})
	if err != nil || !res.GetSuccess() || len(f.notify.calls) != 1 || f.notify.calls[0].tenant != tenantA || f.notify.calls[0].correlation != "exec-9" {
		t.Fatalf("result = %+v, %v", res, err)
	}
	var data map[string]any
	if err := json.Unmarshal(res.GetResultData(), &data); err != nil || data["count"] != 1.0 {
		t.Fatalf("result data = %s, %v", res.GetResultData(), err)
	}
}
