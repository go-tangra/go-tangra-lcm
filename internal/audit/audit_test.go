package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// fakeStore records the batches handed to InsertAuditRows.
type fakeStore struct {
	mu   sync.Mutex
	rows []store.AuditRow
	err  error
	n    int
}

func (f *fakeStore) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, rows...)
	return nil
}

func (f *fakeStore) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.rows) }

func okEvent() Event {
	return Event{EventType: CertificateIssued, TenantID: "t", ActorKind: ActorService, ActorID: "svc", SubjectKind: SubjectCertificate, SubjectID: "c", Outcome: OutcomeOK}
}

func TestValidate(t *testing.T) {
	if err := Validate(okEvent()); err != nil {
		t.Fatal(err)
	}
	bad := []Event{
		{EventType: "channel_created", TenantID: "t", ActorKind: ActorUser, SubjectKind: SubjectCertificate, Outcome: OutcomeOK}, // notification vocab
		{EventType: CertificateIssued, ActorKind: ActorUser, SubjectKind: SubjectCertificate, Outcome: OutcomeOK},                // no tenant
		{EventType: CertificateIssued, TenantID: "t", ActorKind: "robot", SubjectKind: SubjectCertificate, Outcome: OutcomeOK},   // bad actor
		{EventType: CertificateIssued, TenantID: "t", ActorKind: ActorUser, SubjectKind: "channel", Outcome: OutcomeOK},          // bad subject
		{EventType: CertificateIssued, TenantID: "t", ActorKind: ActorUser, SubjectKind: SubjectCertificate, Outcome: "maybe"},   // bad outcome
	}
	for i, e := range bad {
		if err := Validate(e); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, name := range []string{"ca_generated", "backup_exported_with_credentials", "enrollment_refused", "stream_opened"} {
		if !Known(name) {
			t.Errorf("%s unknown", name)
		}
	}
	if Known("channel_created") {
		t.Error("notification vocabulary leaked")
	}
}

func TestGuardDetails(t *testing.T) {
	m := map[string]any{
		"password":   "p",               // contains "password"
		"api_key":    "k",               // contains "key"
		"secret_ref": "s",               // contains "secret"
		"auth_token": "x",               // contains "token"
		"private":    "y",               // contains "private"
		"csr_pem":    "z",               // contains "csr"
		"serial":     "abc123",          // kept
		"host":       "svc.example.org", // kept
		"long":       strings.Repeat("a", 300),
		"nested":     map[string]any{"signing_key": "leak", "fine": "ok"},
		"list":       []any{strings.Repeat("b", 300), "short"},
	}
	var d map[string]any
	if err := json.Unmarshal(guardDetails(m), &d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"password", "api_key", "secret_ref", "auth_token", "private", "csr_pem"} {
		if _, ok := d[k]; ok {
			t.Errorf("%s not dropped", k)
		}
	}
	if d["serial"] != "abc123" || d["host"] != "svc.example.org" {
		t.Errorf("safe values altered: %v / %v", d["serial"], d["host"])
	}
	if len(d["long"].(string)) != 256 {
		t.Errorf("long not truncated: %d", len(d["long"].(string)))
	}
	nested := d["nested"].(map[string]any)
	if _, ok := nested["signing_key"]; ok {
		t.Error("nested forbidden key not dropped")
	}
	if nested["fine"] != "ok" {
		t.Errorf("nested safe value altered: %v", nested["fine"])
	}
	list := d["list"].([]any)
	if len(list[0].(string)) != 256 || list[1] != "short" {
		t.Errorf("list guard: %v", list)
	}
}

func TestRecordBatchAndFlush(t *testing.T) {
	fs := &fakeStore{}
	w := NewWriter(fs, nil)
	ctx := context.Background()
	for i := 0; i < 250; i++ {
		if err := w.Record(ctx, okEvent()); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush(ctx)
	if fs.count() != 250 {
		t.Fatalf("stored %d, want 250", fs.count())
	}
	w.Close()
}

func TestRecordUnknownRejected(t *testing.T) {
	fs := &fakeStore{}
	w := NewWriter(fs, nil)
	defer w.Close()
	if err := w.Record(context.Background(), Event{EventType: "share_created", TenantID: "t", ActorKind: ActorUser, SubjectKind: SubjectCertificate, Outcome: OutcomeOK}); err == nil {
		t.Fatal("unknown event type accepted")
	}
	w.Flush(context.Background())
	if fs.count() != 0 {
		t.Fatalf("rejected event was stored: %d", fs.count())
	}
}

func TestCloseFlushes(t *testing.T) {
	fs := &fakeStore{}
	w := NewWriter(fs, nil)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := w.Record(ctx, Event{EventType: SecretRotated, TenantID: "t", ActorKind: ActorUser, ActorID: "u", SubjectKind: SubjectSecret, SubjectID: "s", Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if fs.count() != 10 {
		t.Fatalf("close did not flush: %d", fs.count())
	}
	w.Close() // idempotent
	if err := w.Record(ctx, okEvent()); err == nil {
		t.Fatal("record after close accepted")
	}
	if w.Dropped() != 1 {
		t.Fatalf("dropped=%d, want 1", w.Dropped())
	}
	w.Flush(ctx) // no-op after close
}

func TestWriterErrorAndOverflow(t *testing.T) {
	fs := &fakeStore{err: errors.New("db down")}
	var mu sync.Mutex
	var got []error
	w := newWriter(fs, func(e error) { mu.Lock(); got = append(got, e); mu.Unlock() }, 2)
	w.start()
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		_ = w.Record(ctx, Event{EventType: AccessRefused, TenantID: "t", ActorKind: ActorUser, SubjectKind: SubjectGrant, Outcome: OutcomeRefused})
	}
	w.Flush(ctx)
	w.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no errors reported")
	}
	if w.Dropped() == 0 {
		t.Fatal("no overflow drop reported")
	}
}

func TestWriterTicker(t *testing.T) {
	fs := &fakeStore{}
	w := newWriter(fs, nil, 10)
	w.tick = 10 * time.Millisecond
	w.start()
	defer w.Close()
	if err := w.Record(context.Background(), Event{EventType: EnrollmentIssued, TenantID: "t", ActorKind: ActorService, SubjectKind: SubjectCertificate, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for fs.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if fs.count() != 1 {
		t.Fatal("ticker did not flush")
	}
}
