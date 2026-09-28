// Package taskexec holds the scheduled task types lcm executes for the
// scheduler module (feature 026). The SDK executor server
// (go-tangra-scheduler sdk pkg/taskexec) verifies the caller and the tenant;
// the handlers here re-validate the payload, scope every query to the request
// tenant and never log or echo payload values (recipient addresses) or
// certificate material.
package taskexec

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
	"github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/schedulerclient"
	sdk "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"
)

// TypeCheckExpiring e-mails a digest of the tenant's expiring certificates.
const TypeCheckExpiring = "lcm:check-expiring-certificates"

// TemplateKey is the notification system template of the digest.
const TemplateKey = "lcm.certificates_expiring"

// Payload bounds.
const (
	DefaultDays   = 7
	MaxDays       = 365
	MaxRecipients = 20
	// DefaultLimit bounds the certificates listed in one digest.
	DefaultLimit = 1000
)

// expiringSchema is the JSON Schema advertised to the scheduler; Handle
// enforces the same rules again.
const expiringSchema = `{"type":"object","required":["recipients"],"properties":{` +
	`"daysBeforeExpiry":{"type":"integer","minimum":1,"maximum":365,"default":7,` +
	`"description":"Report certificates expiring within this many days."},` +
	`"recipients":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string","format":"email"},` +
	`"description":"E-mail addresses that receive the digest (one message each)."}},` +
	`"additionalProperties":false}`

// Descriptors are the task types lcm registers with the scheduler.
func Descriptors() []schedulerclient.Descriptor {
	return []schedulerclient.Descriptor{{
		Type:        TypeCheckExpiring,
		DisplayName: "Notify expiring certificates",
		Description: "E-mails the configured recipients a digest of the tenant's active certificates " +
			"expiring within the horizon (default 7 days).",
		PayloadSchema:   expiringSchema,
		DefaultCron:     "0 8 * * *",
		DefaultMaxRetry: 1,
	}}
}

// Handlers maps the task types to their handlers for sdk.NewServer.
func Handlers(e *Expiring) map[string]sdk.Handler {
	return map[string]sdk.Handler{TypeCheckExpiring: e.Handle}
}

// Certificates is the persistence the handler reads (tenant scope).
type Certificates interface {
	ExpiringCertificates(ctx context.Context, tenantID string, now, before time.Time, limit int) ([]store.IssuedCertificate, error)
	IssuersByIDs(ctx context.Context, tenantID string, ids []string) ([]store.Issuer, error)
}

// Notifier sends one keyed notification (notifyclient.Client).
type Notifier interface {
	SendKey(ctx context.Context, tenantID, key, recipient string, variables map[string]string, correlationID string) (notifyclient.Result, error)
}

// Expiring executes lcm:check-expiring-certificates.
type Expiring struct {
	Repo   Certificates
	Notify Notifier
	Now    func() time.Time // default time.Now
	Limit  int              // default DefaultLimit
	Log    *slog.Logger     // optional; never receives addresses or PEMs
}

func (e *Expiring) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Expiring) limit() int {
	if e.Limit > 0 {
		return e.Limit
	}
	return DefaultLimit
}

func (e *Expiring) warn(ctx context.Context, msg string, args ...any) {
	if e.Log != nil {
		e.Log.WarnContext(ctx, msg, args...)
	}
}

type expiringPayload struct {
	DaysBeforeExpiry int      `json:"daysBeforeExpiry"`
	Recipients       []string `json:"recipients"`
}

// parse decodes and validates the payload; errors never echo values.
func parse(raw json.RawMessage) (days int, recipients []string, err error) {
	var p expiringPayload
	if err := sdk.DecodeStrict(raw, &p); err != nil {
		return 0, nil, err
	}
	days = p.DaysBeforeExpiry
	if days == 0 {
		days = DefaultDays
	}
	if days < 1 || days > MaxDays {
		return 0, nil, fmt.Errorf("daysBeforeExpiry must be within 1..%d", MaxDays)
	}
	if len(p.Recipients) < 1 || len(p.Recipients) > MaxRecipients {
		return 0, nil, fmt.Errorf("recipients must list 1..%d e-mail addresses", MaxRecipients)
	}
	seen := map[string]bool{}
	for i, r := range p.Recipients {
		if !validAddress(r) {
			return 0, nil, fmt.Errorf("recipients[%d] is not a valid e-mail address", i)
		}
		if k := strings.ToLower(r); !seen[k] {
			seen[k] = true
			recipients = append(recipients, r)
		}
	}
	return days, recipients, nil
}

// validAddress accepts a bare addr-spec only (no display name, no CR/LF).
func validAddress(s string) bool {
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// Handle runs one attempt for the request tenant.
func (e *Expiring) Handle(ctx context.Context, req sdk.Request) sdk.Result {
	days, recipients, err := parse(req.Payload)
	if err != nil {
		return sdk.Permanent("invalid payload: " + err.Error())
	}
	if !sdk.ValidTenant(req.TenantID) {
		return sdk.Permanent("a tenant is required")
	}
	if e.Notify == nil {
		return sdk.Permanent("notification module not configured")
	}
	now := e.now()
	limit := e.limit()
	certs, err := e.Repo.ExpiringCertificates(ctx, req.TenantID, now, now.Add(time.Duration(days)*24*time.Hour), limit)
	if err != nil {
		e.warn(ctx, "expiring certificates: listing failed", "tenant", req.TenantID, "execution_id", req.ExecutionID, "err", err)
		return sdk.Retry("listing expiring certificates failed")
	}
	if len(certs) == 0 {
		return sdk.OK(fmt.Sprintf("No certificates expiring within %d days", days))
	}
	issuerNames, err := e.issuerNames(ctx, req.TenantID, certs)
	if err != nil {
		e.warn(ctx, "expiring certificates: issuer lookup failed", "tenant", req.TenantID, "execution_id", req.ExecutionID, "err", err)
		return sdk.Retry("loading certificate issuers failed")
	}
	vars := map[string]string{
		"days":         strconv.Itoa(days),
		"count":        strconv.Itoa(len(certs)),
		"certificates": digest(certs, issuerNames, now, limit),
	}
	head := fmt.Sprintf("Found %d certificate(s) expiring within %d days", len(certs), days)

	sent, retry, failed := 0, 0, 0
	for i, r := range recipients {
		if ctx.Err() != nil {
			retry += len(recipients) - i
			break
		}
		res, err := e.Notify.SendKey(ctx, req.TenantID, TemplateKey, r, vars, req.ExecutionID)
		switch {
		case err != nil:
			code := status.Code(err)
			e.warn(ctx, "expiring certificates: notification refused", "tenant", req.TenantID, "execution_id", req.ExecutionID, "code", code.String())
			return sdk.Permanent("notification refused the digest: " + code.String())
		case res.Sent:
			sent++
		case res.Retryable:
			retry++
		default:
			failed++
		}
	}
	switch {
	case retry > 0:
		return sdk.Retry(fmt.Sprintf("%s; notified %d of %d recipient(s), %d to retry", head, sent, len(recipients), retry))
	case failed > 0:
		return sdk.Permanent(fmt.Sprintf("%s; notified %d of %d recipient(s), %d delivery failure(s)", head, sent, len(recipients), failed))
	}
	ids := make([]string, len(certs))
	for i, c := range certs {
		ids[i] = c.ID
	}
	res := sdk.OK(fmt.Sprintf("%s; notified %d recipient(s)", head, sent))
	res.Data = map[string]any{"count": len(certs), "notified": sent, "certificate_ids": ids}
	return res
}

func (e *Expiring) issuerNames(ctx context.Context, tenantID string, certs []store.IssuedCertificate) (map[string]string, error) {
	seen := map[string]bool{}
	var ids []string
	for _, c := range certs {
		if !seen[c.IssuerID] {
			seen[c.IssuerID] = true
			ids = append(ids, c.IssuerID)
		}
	}
	issuers, err := e.Repo.IssuersByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(issuers))
	for _, i := range issuers {
		names[i.ID] = i.Name
	}
	return names, nil
}

// digest renders one plain-text line per certificate (the notification
// template escapes it); control characters are flattened so a crafted
// subject cannot add lines.
func digest(certs []store.IssuedCertificate, issuers map[string]string, now time.Time, limit int) string {
	lines := make([]string, 0, len(certs)+1)
	for _, c := range certs {
		var b strings.Builder
		b.WriteString("- ")
		b.WriteString(oneLine(certName(c)))
		if sans := sanList(c.SANs); len(sans) > 0 {
			b.WriteString(" (" + oneLine(strings.Join(sans, ", ")) + ")")
		}
		issuer := issuers[c.IssuerID]
		if issuer == "" {
			issuer = "unknown"
		}
		left := int(math.Ceil(c.NotAfter.Sub(now).Hours() / 24))
		renew := "off"
		if c.AutoRenew {
			renew = "on"
		}
		fmt.Fprintf(&b, " — issuer %s — expires %s (%d day(s)) — auto-renew %s",
			oneLine(issuer), c.NotAfter.UTC().Format(time.RFC3339), left, renew)
		lines = append(lines, b.String())
	}
	if len(certs) >= limit {
		lines = append(lines, fmt.Sprintf("(list limited to the first %d certificates)", limit))
	}
	return strings.Join(lines, "\n")
}

// certName is the subject CN (or the subject), else the SPIFFE id, else the id.
func certName(c store.IssuedCertificate) string {
	for _, part := range strings.Split(c.Subject, ",") {
		if cn, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok && cn != "" {
			return cn
		}
	}
	switch {
	case c.Subject != "":
		return c.Subject
	case c.SpiffeID != "":
		return c.SpiffeID
	}
	return c.ID
}

func sanList(raw []byte) []string {
	var sans []string
	if json.Unmarshal(raw, &sans) != nil {
		return nil
	}
	return sans
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
