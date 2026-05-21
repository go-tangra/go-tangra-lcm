package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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

	// LCM is unusual in that it doesn't issue itself a per-module
	// client cert at platform bootstrap (it's the CA — nothing else
	// signs for it). Its /app/data/server/server.crt has EKU=ServerAuth
	// only, so passing it as a client cert gets rejected with "tls: bad
	// certificate" on the scheduler side.
	//
	// Fix: mint one on demand using LCM's own CA. The cert is written
	// to <certsDir>/lcm/lcm.{crt,key} so subsequent boots reuse it
	// (and any future flow that wants an LCM client cert lands at the
	// conventional path).
	lcmCertPath := filepath.Join(certsDir, "lcm", "lcm.crt")
	lcmKeyPath := filepath.Join(certsDir, "lcm", "lcm.key")
	if err := ensureLcmClientCert(certsDir, lcmCertPath, lcmKeyPath, l); err != nil {
		l.Warnf("Failed to ensure LCM client cert, falling back to insecure: %v", err)
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	clientCert, err := tls.LoadX509KeyPair(lcmCertPath, lcmKeyPath)
	if err != nil {
		l.Warnf("Failed to load LCM client cert from %s: %v", lcmCertPath, err)
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	l.Infof("Using client cert from %s for scheduler", lcmCertPath)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "scheduler-service",
		MinVersion:   tls.VersionTLS12,
	}

	l.Info("Using mTLS credentials for scheduler connection")
	return grpc.WithTransportCredentials(credentials.NewTLS(cfg))
}

// ensureLcmClientCert makes sure <certsDir>/lcm/lcm.{crt,key} exists and is
// a valid CA-signed client cert. If the cert already exists and hasn't
// expired, it's left alone. If it's missing or invalid, we mint a new
// one using LCM's own CA (which we have full read access to since we
// ARE that CA).
//
// This is the standard "LCM signs its own client cert" workaround for the
// chicken-and-egg problem: every other module gets a per-module client
// cert via the BootstrapCertificates RPC at platform install time, but
// LCM has nobody to bootstrap from.
func ensureLcmClientCert(certsDir, certPath, keyPath string, l *log.Helper) error {
	// Reuse if present and still valid (>30 day buffer so we re-mint
	// well before expiry).
	if data, err := os.ReadFile(certPath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if cert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				if time.Now().Add(30 * 24 * time.Hour).Before(cert.NotAfter) {
					if _, kerr := os.Stat(keyPath); kerr == nil {
						return nil
					}
				}
			}
		}
		l.Info("Existing lcm.crt is missing, unparseable or near-expiry — regenerating")
	}

	caCertPath := filepath.Join(certsDir, "ca", "ca.crt")
	caKeyPath := filepath.Join(certsDir, "ca", "ca.key")

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert at %s: %w", caCertPath, err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("read CA key at %s: %w", caKeyPath, err)
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return fmt.Errorf("CA cert PEM has no decodable block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("CA key PEM has no decodable block")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Older deployments may have used PKCS1; try it as a fallback.
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA key (PKCS8 + PKCS1 both failed): %w", err)
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		// Subject mirrors the per-module client cert convention used
		// by BootstrapService.generateClientCert (O=LCM, OU=<module>,
		// CN=lcm-<module>). lcm-client makes the dual-role nature
		// obvious in audit logs.
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Client"},
			CommonName:         "lcm-client",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create client cert: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(certPath), err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o640); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal client key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyPath, keyPEMBytes, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	l.Infof("Minted LCM client cert at %s (CN=lcm-client, EKU=ClientAuth, NotAfter=%s)",
		certPath, template.NotAfter.Format(time.RFC3339))
	return nil
}
