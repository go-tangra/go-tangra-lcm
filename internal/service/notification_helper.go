package service

import (
	"context"
	"fmt"
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
	}
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

// SendCertificateIssued sends a notification that a certificate has been issued.
func (h *NotificationHelper) SendCertificateIssued(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}

	templateID, err := h.EnsureTemplate(ctx, templateNameCertIssued)
	if err != nil {
		h.log.Warnf("Failed to ensure cert-issued template: %v", err)
		return nil
	}

	platformCtx := client.DetachedMetadataContext(ctx, 0)
	_, err = h.notificationClient.SendNotification(platformCtx, templateID, recipient, vars)
	if err != nil {
		h.log.Warnf("Failed to send cert-issued notification to %s: %v", recipient, err)
	}
	return err
}

// SendCertificateRenewed sends a notification that a certificate has been renewed.
func (h *NotificationHelper) SendCertificateRenewed(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}

	templateID, err := h.EnsureTemplate(ctx, templateNameCertRenewed)
	if err != nil {
		h.log.Warnf("Failed to ensure cert-renewed template: %v", err)
		return nil
	}

	platformCtx := client.DetachedMetadataContext(ctx, 0)
	_, err = h.notificationClient.SendNotification(platformCtx, templateID, recipient, vars)
	if err != nil {
		h.log.Warnf("Failed to send cert-renewed notification to %s: %v", recipient, err)
	}
	return err
}

// SendCertificateFailed sends a notification that a certificate operation has failed.
func (h *NotificationHelper) SendCertificateFailed(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}

	templateID, err := h.EnsureTemplate(ctx, templateNameCertFailed)
	if err != nil {
		h.log.Warnf("Failed to ensure cert-failed template: %v", err)
		return nil
	}

	platformCtx := client.DetachedMetadataContext(ctx, 0)
	_, err = h.notificationClient.SendNotification(platformCtx, templateID, recipient, vars)
	if err != nil {
		h.log.Warnf("Failed to send cert-failed notification to %s: %v", recipient, err)
	}
	return err
}
