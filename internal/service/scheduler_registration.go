package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// RegisterTasksWithScheduler tells the scheduler which task types LCM can
// execute. Runs in a background goroutine and retries — the scheduler may
// boot after LCM and there's no hard ordering between the two services.
//
// Mirrors the registration pattern in go-tangra-backup; the only LCM-
// specific bit is the descriptor list.
func RegisterTasksWithScheduler(logger log.Logger) {
	l := log.NewHelper(log.With(logger, "module", "scheduler-registration/lcm-service"))

	endpoint := os.Getenv("SCHEDULER_GRPC_ENDPOINT")
	if endpoint == "" {
		l.Info("SCHEDULER_GRPC_ENDPOINT not set, skipping task type registration")
		return
	}

	go func() {
		// Same wait + retry rhythm as the backup module so the two
		// services don't fight for the scheduler's first few seconds.
		time.Sleep(10 * time.Second)

		for attempt := 0; attempt < 30; attempt++ {
			if err := doRegisterLcmTasks(endpoint, l); err != nil {
				l.Warnf("Task type registration attempt %d failed: %v", attempt+1, err)
				time.Sleep(10 * time.Second)
				continue
			}
			return
		}
		l.Error("Failed to register task types with scheduler after 30 attempts")
	}()
}

func doRegisterLcmTasks(endpoint string, l *log.Helper) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(endpoint, loadSchedulerTLS(l))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := commonV1.NewTaskTypeRegistrationServiceClient(conn)

	resp, err := client.RegisterTaskTypes(ctx, &commonV1.RegisterTaskTypesRequest{
		ModuleId: "lcm",
		TaskTypes: []*commonV1.TaskTypeDescriptor{
			{
				TaskType:    "lcm:check-expiring-certificates",
				DisplayName: "Notify expiring certificates",
				Description: "Scan all issued (non-mTLS) certificates and email LCM/platform admins about any cert expiring within the configured horizon.",
				// daysBeforeExpiry default mirrors the executor default
				// — 7 days. Operators can override per-task in the
				// scheduler UI.
				PayloadSchema:   `{"type":"object","properties":{"daysBeforeExpiry":{"type":"integer","default":7,"minimum":1,"maximum":365}}}`,
				DefaultCron:     "0 8 * * *",
				DefaultMaxRetry: 1,
			},
		},
	})
	if err != nil {
		return err
	}

	l.Infof("Registered %d task type(s) with scheduler: %s", resp.GetRegisteredCount(), resp.GetMessage())
	return nil
}

// loadSchedulerTLS mirrors the backup module's helper: try mTLS using the
// per-module client cert provisioned by LCM bootstrap, fall back to
// insecure if anything's missing.
func loadSchedulerTLS(l *log.Helper) grpc.DialOption {
	certsDir := os.Getenv("CERTS_DIR")
	if certsDir == "" {
		certsDir = "/app/certs"
	}

	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca", "ca.crt"))
	if err != nil {
		l.Info("No CA cert found, using insecure credentials for scheduler")
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		l.Warn("Failed to parse CA cert, using insecure credentials for scheduler")
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "lcm", "lcm.crt"),
		filepath.Join(certsDir, "lcm", "lcm.key"),
	)
	if err != nil {
		l.Info("No client cert found, using insecure credentials for scheduler")
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "scheduler-service",
		MinVersion:   tls.VersionTLS12,
	}

	l.Info("Using mTLS credentials for scheduler connection")
	return grpc.WithTransportCredentials(credentials.NewTLS(cfg))
}
