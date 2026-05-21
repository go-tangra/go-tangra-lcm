package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	appViewer "github.com/go-tangra/go-tangra-common/viewer"

	"github.com/go-tangra/go-tangra-lcm/internal/data"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// TaskExecutor implements common.service.v1.TaskExecutorService and handles
// every lcm:* task type the scheduler can fire. Today only the
// "lcm:check-expiring-certificates" task is supported.
type TaskExecutor struct {
	commonV1.UnimplementedTaskExecutorServiceServer

	log         *log.Helper
	issuedCerts *data.IssuedCertificateRepo
	notif       *NotificationHelper
}

// NewTaskExecutor wires the LCM task executor. notif is allowed to be nil
// (configurations without a notification service degrade to no-op email
// delivery — the task still runs and logs the at-risk certs).
func NewTaskExecutor(
	ctx *bootstrap.Context,
	issuedCerts *data.IssuedCertificateRepo,
	notif *NotificationHelper,
) *TaskExecutor {
	return &TaskExecutor{
		log:         ctx.NewLoggerHelper("task-executor/lcm-service"),
		issuedCerts: issuedCerts,
		notif:       notif,
	}
}

// ExecuteTask is the entry point the scheduler calls via gRPC.
func (e *TaskExecutor) ExecuteTask(
	ctx context.Context,
	req *commonV1.ExecuteTaskRequest,
) (*commonV1.ExecuteTaskResponse, error) {
	e.log.Infof("Executing task %s (execution=%s, attempt=%d/%d, tenant=%d)",
		req.GetTaskType(), req.GetExecutionId(), req.GetAttempt(), req.GetMaxAttempts(), req.GetTenantId())

	switch req.GetTaskType() {
	case "lcm:check-expiring-certificates":
		return e.handleCheckExpiring(ctx, req)
	default:
		return &commonV1.ExecuteTaskResponse{
			Success:          false,
			PermanentFailure: true,
			Message:          fmt.Sprintf("unknown task type: %s", req.GetTaskType()),
		}, nil
	}
}

// CheckExpiringConfig is the payload schema for lcm:check-expiring-certificates.
type CheckExpiringConfig struct {
	// How many days before expiry to start nagging. Default 7.
	DaysBeforeExpiry int `json:"daysBeforeExpiry"`
}

func (e *TaskExecutor) handleCheckExpiring(
	ctx context.Context,
	req *commonV1.ExecuteTaskRequest,
) (*commonV1.ExecuteTaskResponse, error) {
	cfg := CheckExpiringConfig{DaysBeforeExpiry: 7}
	if len(req.GetPayload()) > 0 {
		if err := json.Unmarshal(req.GetPayload(), &cfg); err != nil {
			return &commonV1.ExecuteTaskResponse{
				Success:          false,
				PermanentFailure: true,
				Message:          fmt.Sprintf("invalid payload: %v", err),
			}, nil
		}
	}
	if cfg.DaysBeforeExpiry <= 0 {
		cfg.DaysBeforeExpiry = 7
	}

	// The repo enforces ent privacy via viewer context; the scheduler
	// callbacks run without a user identity, so we elevate to system.
	sysCtx := appViewer.NewSystemViewerContext(ctx)

	horizon := time.Duration(cfg.DaysBeforeExpiry) * 24 * time.Hour
	certs, err := e.issuedCerts.ListExpiringWithin(sysCtx, horizon)
	if err != nil {
		return &commonV1.ExecuteTaskResponse{
			Success: false,
			Message: fmt.Sprintf("failed to list expiring certificates: %v", err),
		}, nil
	}

	if len(certs) == 0 {
		msg := fmt.Sprintf("No certificates expiring within %d days", cfg.DaysBeforeExpiry)
		e.log.Info(msg)
		return &commonV1.ExecuteTaskResponse{
			Success: true,
			Message: msg,
		}, nil
	}

	// Resolve recipients once. ResolveRecipients returns the union of
	// the issuer-scoped email (empty here — no specific issuer) and the
	// platform admins. If the list is empty there's nowhere to notify,
	// but we still log the at-risk certs and finish successfully so the
	// scheduler doesn't keep retrying.
	var recipients []string
	if e.notif != nil {
		recipients = e.notif.ResolveRecipients(sysCtx, "")
	}

	now := time.Now()
	notified := 0
	skipped := 0
	var lastErr error
	for _, cert := range certs {
		if cert.ExpiresAt.IsZero() {
			skipped++
			continue
		}
		// Round-up so a cert expiring in 6h 5m reads as "1 day(s)"
		// instead of "0 day(s)" — that's the operator-friendly read.
		daysRemaining := int(math.Ceil(cert.ExpiresAt.Sub(now).Hours() / 24))
		if daysRemaining < 0 {
			// Past expiry — covered by other workflows; skip.
			skipped++
			continue
		}

		vars := map[string]string{
			"CommonName":    cert.CommonName,
			"Domains":       strings.Join(cert.Domains, ", "),
			"IssuerName":    cert.IssuerName,
			"ExpiresAt":     cert.ExpiresAt.Format(time.RFC3339),
			"DaysRemaining": strconv.Itoa(daysRemaining),
			"AutoRenew":     strconv.FormatBool(cert.AutoRenewEnabled),
		}

		e.log.Infof("Cert %s (%s) expires in %d day(s) at %s",
			cert.ID, cert.CommonName, daysRemaining, cert.ExpiresAt.Format(time.RFC3339))

		if e.notif == nil || len(recipients) == 0 {
			// No notifier wired or no recipients — log only.
			continue
		}

		if notifyErr := e.notif.NotifyCertificateExpiring(sysCtx, recipients, vars); notifyErr != nil {
			// Don't abort the whole sweep on one failed send — the
			// remaining certs still deserve a try. Capture the last
			// error to surface in the response.
			e.log.Errorf("Failed to send expiring notification for cert %s: %v", cert.ID, notifyErr)
			lastErr = notifyErr
			continue
		}
		notified++
	}

	msg := fmt.Sprintf("Found %d cert(s) expiring within %d days; notified=%d skipped=%d",
		len(certs), cfg.DaysBeforeExpiry, notified, skipped)
	if lastErr != nil {
		return &commonV1.ExecuteTaskResponse{
			Success: false,
			Message: fmt.Sprintf("%s; last notification error: %v", msg, lastErr),
		}, nil
	}
	return &commonV1.ExecuteTaskResponse{
		Success: true,
		Message: msg,
	}, nil
}
