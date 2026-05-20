package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/go-tangra/go-tangra-lcm/internal/client"

	notificationv1 "buf.build/gen/go/go-tangra/notification/protocolbuffers/go/notification/service/v1"
)

// Template names registered in the notification service.
const (
	templateNameCertIssued  = "lcm-cert-issued-template"
	templateNameCertRenewed = "lcm-cert-renewed-template"
	templateNameCertFailed  = "lcm-cert-failed-template"
	notifChannelName        = "Default SMTP"
)

// --- Certificate Issued template ---

var certIssuedSubject = `Certificate issued: {{.CommonName}}`

var certIssuedBody = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Certificate Issued Successfully</h2>
  <p>Hello,</p>
  <p>A new TLS certificate has been issued for <strong>{{.CommonName}}</strong>.</p>
  <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Common Name</td><td style="padding: 8px; border: 1px solid #eee;">{{.CommonName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Domains</td><td style="padding: 8px; border: 1px solid #eee;">{{.Domains}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Issuer</td><td style="padding: 8px; border: 1px solid #eee;">{{.IssuerName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Expires At</td><td style="padding: 8px; border: 1px solid #eee;">{{.ExpiresAt}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Key Type</td><td style="padding: 8px; border: 1px solid #eee;">{{.KeyType}}</td></tr>
  </table>
  <p>The certificate is ready to use and can be downloaded from the LCM dashboard.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 11px;">This is an automated message from GoTangra Certificate Lifecycle Management.</p>
</body>
</html>`

// --- Certificate Renewed template ---

var certRenewedSubject = `Certificate renewed: {{.CommonName}}`

var certRenewedBody = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Certificate Renewed Successfully</h2>
  <p>Hello,</p>
  <p>The TLS certificate for <strong>{{.CommonName}}</strong> has been renewed.</p>
  <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Common Name</td><td style="padding: 8px; border: 1px solid #eee;">{{.CommonName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Domains</td><td style="padding: 8px; border: 1px solid #eee;">{{.Domains}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Issuer</td><td style="padding: 8px; border: 1px solid #eee;">{{.IssuerName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">New Expiry</td><td style="padding: 8px; border: 1px solid #eee;">{{.ExpiresAt}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Previous Expiry</td><td style="padding: 8px; border: 1px solid #eee;">{{.PreviousExpiresAt}}</td></tr>
  </table>
  <p>The renewed certificate is now active.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 11px;">This is an automated message from GoTangra Certificate Lifecycle Management.</p>
</body>
</html>`

// --- Certificate Failed template ---

var certFailedSubject = `Certificate operation failed: {{.CommonName}}`

var certFailedBody = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <h2 style="color: #FF4D4F;">Certificate Operation Failed</h2>
  <p>Hello,</p>
  <p>A certificate operation for <strong>{{.CommonName}}</strong> has failed.</p>
  <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Common Name</td><td style="padding: 8px; border: 1px solid #eee;">{{.CommonName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Domains</td><td style="padding: 8px; border: 1px solid #eee;">{{.Domains}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Issuer</td><td style="padding: 8px; border: 1px solid #eee;">{{.IssuerName}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold;">Operation</td><td style="padding: 8px; border: 1px solid #eee;">{{.Operation}}</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #eee; font-weight: bold; color: #FF4D4F;">Error</td><td style="padding: 8px; border: 1px solid #eee; color: #FF4D4F;">{{.ErrorMessage}}</td></tr>
  </table>
  <p>Please check the LCM dashboard for more details and consider retrying the operation.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 11px;">This is an automated message from GoTangra Certificate Lifecycle Management.</p>
</body>
</html>`

// templateDef defines a notification template to be lazily registered.
type templateDef struct {
	name      string
	subject   string
	body      string
	variables string
}

var lcmTemplateDefs = map[string]templateDef{
	templateNameCertIssued: {
		name:      templateNameCertIssued,
		subject:   certIssuedSubject,
		body:      certIssuedBody,
		variables: "CommonName,Domains,IssuerName,ExpiresAt,KeyType",
	},
	templateNameCertRenewed: {
		name:      templateNameCertRenewed,
		subject:   certRenewedSubject,
		body:      certRenewedBody,
		variables: "CommonName,Domains,IssuerName,ExpiresAt,PreviousExpiresAt",
	},
	templateNameCertFailed: {
		name:      templateNameCertFailed,
		subject:   certFailedSubject,
		body:      certFailedBody,
		variables: "CommonName,Domains,IssuerName,Operation,ErrorMessage",
	},
}

// NotificationHelper manages lazy registration and sending of LCM notification templates.
type NotificationHelper struct {
	log                *log.Helper
	notificationClient *client.NotificationClient

	mu          sync.Mutex
	templateIDs map[string]string // template name -> resolved ID

	// defaultRecipients is the platform-wide fallback mailing list for
	// every cert event (issued, renewed, failed, rejected). Loaded once
	// from LCM_NOTIFICATION_RECIPIENTS at construction time. Combined
	// with issuer-scoped recipients (e.g. ACME email) per send.
	defaultRecipients []string
}

// NewNotificationHelper creates a NotificationHelper.
func NewNotificationHelper(log *log.Helper, notificationClient *client.NotificationClient) *NotificationHelper {
	if notificationClient == nil {
		return nil
	}
	return &NotificationHelper{
		log:                log,
		notificationClient: notificationClient,
		templateIDs:        make(map[string]string),
		defaultRecipients:  parseRecipientsEnv(os.Getenv("LCM_NOTIFICATION_RECIPIENTS")),
	}
}

// parseRecipientsEnv splits a comma-separated list of email addresses,
// trims whitespace, drops empties, and lowercases for stable dedup keys.
func parseRecipientsEnv(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		e := strings.ToLower(strings.TrimSpace(p))
		if e == "" {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

// ResolveRecipients returns the deduped union of an issuer-scoped email
// (e.g. the ACME account email) and the platform-wide default recipients.
// Both inputs are optional — passing "" or nil collapses to whatever the
// other source provides. An empty result means there is nowhere to
// notify; callers should log a WARN so the silent-drop is visible.
func (h *NotificationHelper) ResolveRecipients(issuerScoped string) []string {
	if h == nil {
		return nil
	}
	seen := make(map[string]struct{}, 1+len(h.defaultRecipients))
	out := make([]string, 0, 1+len(h.defaultRecipients))
	add := func(s string) {
		e := strings.ToLower(strings.TrimSpace(s))
		if e == "" {
			return
		}
		if _, dup := seen[e]; dup {
			return
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	add(issuerScoped)
	for _, r := range h.defaultRecipients {
		add(r)
	}
	return out
}

// EnsureTemplate resolves (or creates) a notification template by name.
// Uses platform admin context (tenant 0) because templates are platform-level resources.
func (h *NotificationHelper) EnsureTemplate(ctx context.Context, templateName string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if id, ok := h.templateIDs[templateName]; ok {
		return id, nil
	}

	def, ok := lcmTemplateDefs[templateName]
	if !ok {
		return "", fmt.Errorf("unknown template name: %s", templateName)
	}

	h.log.Infof("Resolving notification template %q...", templateName)

	platformCtx := client.DetachedMetadataContext(ctx, 0)

	tmpl, err := h.notificationClient.FindTemplateByName(platformCtx, templateName)
	if err != nil {
		return "", fmt.Errorf("search notification template: %w", err)
	}
	if tmpl != nil {
		h.templateIDs[templateName] = tmpl.GetId()
		h.log.Infof("Found existing notification template %q: %s", templateName, tmpl.GetId())
		return tmpl.GetId(), nil
	}

	channelID, err := h.notificationClient.FindChannelByName(platformCtx, notifChannelName)
	if err != nil {
		return "", fmt.Errorf("find channel %q: %w", notifChannelName, err)
	}

	created, err := h.notificationClient.CreateTemplate(platformCtx, &notificationv1.CreateTemplateRequest{
		Name:      def.name,
		ChannelId: channelID,
		Subject:   def.subject,
		Body:      def.body,
		Variables: def.variables,
		IsDefault: false,
	})
	if err != nil {
		return "", fmt.Errorf("create notification template: %w", err)
	}

	h.templateIDs[templateName] = created.GetId()
	h.log.Infof("Created notification template %q: %s", templateName, created.GetId())
	return created.GetId(), nil
}

// notifyAll renders the template and dispatches to every recipient.
// Returns the last send error encountered (if any) and a count of
// successful deliveries — useful for callers that want to react to
// total-silent-drop scenarios. Errors on individual recipients are
// logged at ERROR level (was WARN) so they surface in monitoring; we
// continue past the failure so a single bad address doesn't prevent
// other recipients from being notified.
//
// kind is the human-readable event name used in log lines (e.g.
// "cert-issued"). recipients is expected to already be deduped by
// ResolveRecipients.
func (h *NotificationHelper) notifyAll(ctx context.Context, kind, templateName string, recipients []string, vars map[string]string) (int, error) {
	if h == nil {
		return 0, nil
	}
	if len(recipients) == 0 {
		// Strict mode: surface the silent drop. Without recipients
		// configured there is nowhere to send, so the operator must
		// explicitly opt in via LCM_NOTIFICATION_RECIPIENTS or by
		// supplying an issuer-scoped email.
		h.log.Warnf("%s notification has no recipients (set LCM_NOTIFICATION_RECIPIENTS or configure an issuer email)", kind)
		return 0, nil
	}

	templateID, err := h.EnsureTemplate(ctx, templateName)
	if err != nil {
		h.log.Errorf("Failed to ensure %s template: %v", kind, err)
		return 0, err
	}

	platformCtx := client.DetachedMetadataContext(ctx, 0)

	sent := 0
	var lastErr error
	for _, r := range recipients {
		if _, sendErr := h.notificationClient.SendNotification(platformCtx, templateID, r, vars); sendErr != nil {
			h.log.Errorf("Failed to send %s notification to %s: %v", kind, r, sendErr)
			lastErr = sendErr
			continue
		}
		sent++
	}
	if sent == 0 && lastErr != nil {
		return 0, fmt.Errorf("%s notification failed for all %d recipient(s): %w", kind, len(recipients), lastErr)
	}
	return sent, nil
}

// NotifyCertificateIssued sends a "certificate issued" notification to every
// recipient. Use ResolveRecipients to build the list from an issuer-scoped
// email + platform defaults.
func (h *NotificationHelper) NotifyCertificateIssued(ctx context.Context, recipients []string, vars map[string]string) error {
	if h == nil {
		return nil
	}
	_, err := h.notifyAll(ctx, "cert-issued", templateNameCertIssued, recipients, vars)
	return err
}

// NotifyCertificateRenewed sends a "certificate renewed" notification to every recipient.
func (h *NotificationHelper) NotifyCertificateRenewed(ctx context.Context, recipients []string, vars map[string]string) error {
	if h == nil {
		return nil
	}
	_, err := h.notifyAll(ctx, "cert-renewed", templateNameCertRenewed, recipients, vars)
	return err
}

// NotifyCertificateFailed sends a "certificate failed" notification to every
// recipient. Used for both transient failures (ACME 429, signing errors) and
// hard rejections of mTLS certificate requests by admins.
func (h *NotificationHelper) NotifyCertificateFailed(ctx context.Context, recipients []string, vars map[string]string) error {
	if h == nil {
		return nil
	}
	_, err := h.notifyAll(ctx, "cert-failed", templateNameCertFailed, recipients, vars)
	return err
}

// SendCertificateIssued is a single-recipient wrapper around the new
// NotifyCertificateIssued API; kept for backwards compatibility with the
// older call sites that still pass a single recipient string.
func (h *NotificationHelper) SendCertificateIssued(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}
	return h.NotifyCertificateIssued(ctx, []string{recipient}, vars)
}

// SendCertificateRenewed is the single-recipient wrapper around NotifyCertificateRenewed.
func (h *NotificationHelper) SendCertificateRenewed(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}
	return h.NotifyCertificateRenewed(ctx, []string{recipient}, vars)
}

// SendCertificateFailed is the single-recipient wrapper around NotifyCertificateFailed.
func (h *NotificationHelper) SendCertificateFailed(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}
	return h.NotifyCertificateFailed(ctx, []string{recipient}, vars)
}
