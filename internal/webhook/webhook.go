// Package webhook manages outbound callback subscriptions and delivers
// HMAC-signed lifecycle events to them. The signing secret is write-only:
// sealed at rest with a per-row envelope and NEVER returned in a view or echoed
// in an error (SR-001). Delivery signs the payload with HMAC-SHA256, retries on
// transient failures with capped exponential backoff, and scrubs the secret
// from every log line and error. Every operation is tenant-scoped (RLS) and the
// gateway gates the browser routes with webhooks:manage.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// Event types are the closed set a webhook may subscribe to.
const (
	EventIssued  = "certificate.issued"
	EventRenewed = "certificate.renewed"
	EventRevoked = "certificate.revoked"
	EventFailed  = "certificate.failed"
)

// MaxPayloadBytes bounds a delivered payload (64 KiB).
const MaxPayloadBytes = 64 << 10

const (
	maxURLBytes    = 2048
	deliverTimeout = 10 * time.Second
	baseBackoff    = 50 * time.Millisecond
	maxBackoff     = 2 * time.Second
	defaultTries   = 3
)

// Errors.
var (
	// ErrTooLarge rejects an oversize payload.
	ErrTooLarge = errors.New("webhook: payload exceeds 64 KiB")
)

// ValidationError is a rejected input (field + message).
type ValidationError struct{ Field, Message string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// ConflictError reports a name clash.
type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return e.Message }

func validEvent(t string) bool {
	switch t {
	case EventIssued, EventRenewed, EventRevoked, EventFailed:
		return true
	}
	return false
}

// repoStore is the persistence the service needs (repo.Webhooks satisfies it).
type repoStore interface {
	InsertWebhook(ctx context.Context, w store.WebhookEndpoint) error
	GetWebhook(ctx context.Context, tenantID, id string) (store.WebhookEndpoint, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]store.WebhookEndpoint, error)
	WebhooksForEvent(ctx context.Context, tenantID, eventType string) ([]store.WebhookEndpoint, error)
	DeleteWebhook(ctx context.Context, tenantID, id string) error
}

// Service manages webhook endpoints and delivers events to them.
type Service struct {
	st      repoStore
	env     *sealed.Envelope
	audit   *audit.Writer
	now     func() time.Time
	client  *http.Client
	tries   int
	backoff time.Duration
}

// New builds the service with a bounded HTTP client.
func New(st repoStore, env *sealed.Envelope, aw *audit.Writer, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		st: st, env: env, audit: aw, now: clock,
		client:  &http.Client{Timeout: deliverTimeout},
		tries:   defaultTries,
		backoff: baseBackoff,
	}
}

// Input creates a webhook endpoint. Secret is the HMAC signing key; if empty a
// strong random one is generated. It is sealed and never echoed back.
type Input struct {
	Name       string
	URL        string
	EventTypes []string
	Secret     string
}

// View is a webhook endpoint as returned to clients. The HMAC secret is
// write-only and NEVER present here (SR-001).
type View struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"event_types"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Create registers a webhook endpoint, sealing its signing secret.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in Input) (View, error) {
	if l := len(in.Name); l < 1 || l > 100 {
		return View{}, &ValidationError{Field: "name", Message: "name must be 1..100 chars"}
	}
	if err := validateURL(in.URL); err != nil {
		return View{}, err
	}
	if len(in.EventTypes) == 0 {
		return View{}, &ValidationError{Field: "event_types", Message: "at least one event type is required"}
	}
	events := make([]string, 0, len(in.EventTypes))
	seen := map[string]struct{}{}
	for _, e := range in.EventTypes {
		if !validEvent(e) {
			return View{}, &ValidationError{Field: "event_types", Message: "unknown event type " + e}
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		events = append(events, e)
	}
	secret := in.Secret
	if secret == "" {
		secret = generateSecret()
	}
	id := store.NewID()
	blob, err := s.env.Seal([]byte(secret), sealed.ADWebhook(id))
	if err != nil {
		return View{}, err
	}
	actor := subj.ActorID()
	row := store.WebhookEndpoint{ID: id, TenantID: subj.TenantID, Name: in.Name, URL: in.URL, EventTypes: events, SecretSealed: blob, Enabled: true, CreatedBy: &actor, UpdatedBy: &actor}
	if err := s.st.InsertWebhook(ctx, row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return View{}, &ConflictError{Message: "a webhook with that name already exists"}
		}
		return View{}, err
	}
	s.record(ctx, subj, audit.WebhookCreated, id, in.Name)
	row, err = s.st.GetWebhook(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, err
	}
	return view(row), nil
}

// List returns the tenant's webhook endpoints (secrets never present).
func (s *Service) List(ctx context.Context, subj authz.Subjects) ([]View, error) {
	rows, err := s.st.ListWebhooks(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rows))
	for _, r := range rows {
		out = append(out, view(r))
	}
	return out, nil
}

// Delete removes a webhook endpoint.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	row, err := s.st.GetWebhook(ctx, subj.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.st.DeleteWebhook(ctx, subj.TenantID, id); err != nil {
		return err
	}
	s.record(ctx, subj, audit.WebhookDeleted, id, row.Name)
	return nil
}

// Deliver posts payload to every enabled endpoint subscribed to eventType,
// signing each request with the endpoint's HMAC secret. It is safe to call from
// a goroutine and never panics on a dead endpoint: transport failures and 5xx
// responses are retried with capped exponential backoff, 4xx responses are
// final, and the secret is never included in a returned error. The returned
// error joins the per-endpoint failures (nil when all succeed).
func (s *Service) Deliver(ctx context.Context, tenantID, eventType string, payload []byte) error {
	if len(payload) > MaxPayloadBytes {
		return ErrTooLarge
	}
	endpoints, err := s.st.WebhooksForEvent(ctx, tenantID, eventType)
	if err != nil {
		return err
	}
	var errs []error
	for _, ep := range endpoints {
		if err := s.deliverOne(ctx, ep, eventType, payload); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// deliverOne signs and posts to a single endpoint with bounded retries. No
// error it returns contains the signing secret.
func (s *Service) deliverOne(ctx context.Context, ep store.WebhookEndpoint, eventType string, payload []byte) error {
	secret, err := s.env.Open(ep.SecretSealed, sealed.ADWebhook(ep.ID))
	if err != nil {
		return fmt.Errorf("webhook %s: signing secret could not be opened", ep.ID)
	}
	sig := Sign(secret, payload)
	tries := s.tries
	if tries < 1 {
		tries = 1
	}
	var lastErr error
	for attempt := 0; attempt < tries; attempt++ {
		if attempt > 0 {
			if err := s.wait(ctx, attempt); err != nil {
				return err
			}
		}
		status, err := s.post(ctx, ep.URL, eventType, sig, payload)
		switch {
		case err != nil:
			// transport error: retry.
			lastErr = fmt.Errorf("webhook %s: delivery failed: %w", ep.ID, err)
		case status < 300:
			return nil
		case status >= 400 && status < 500:
			// client error: give up.
			return fmt.Errorf("webhook %s: endpoint returned status %d", ep.ID, status)
		default:
			// 5xx (or 3xx we did not follow): retry.
			lastErr = fmt.Errorf("webhook %s: endpoint returned status %d", ep.ID, status)
		}
	}
	return lastErr
}

func (s *Service) post(ctx context.Context, target, eventType, sig string, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LCM-Event", eventType)
	req.Header.Set("X-LCM-Signature", sig)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// wait sleeps the capped exponential backoff for the given attempt, or returns
// early if the context is cancelled.
func (s *Service) wait(ctx context.Context, attempt int) error {
	d := s.backoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= maxBackoff {
			d = maxBackoff
			break
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Sign returns the HMAC-SHA256 of payload keyed by secret, as "sha256=<hex>".
// Exported for unit tests and fuzzing.
func Sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) record(ctx context.Context, subj authz.Subjects, t audit.EventType, id, name string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: t, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectWebhook, SubjectID: id, SubjectName: name, Outcome: audit.OutcomeOK,
	})
}

func validateURL(raw string) error {
	if raw == "" {
		return &ValidationError{Field: "url", Message: "url is required"}
	}
	if len(raw) > maxURLBytes {
		return &ValidationError{Field: "url", Message: "url must be at most 2048 chars"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return &ValidationError{Field: "url", Message: "url must be an absolute http(s) URL"}
	}
	return nil
}

// generateSecret returns a 32-byte random signing secret as hex.
func generateSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func view(r store.WebhookEndpoint) View {
	ev := r.EventTypes
	if ev == nil {
		ev = []string{}
	}
	return View{ID: r.ID, Name: r.Name, URL: r.URL, EventTypes: ev, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}
