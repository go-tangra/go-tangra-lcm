package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
)

// startEnrollListener runs a dedicated, server-auth-only (tls.NoClientCert) TLS
// listener serving ONLY POST /api/lcm/v1/enroll. It exists so a service with no
// SVID yet — notably the gateway, which cannot enroll through itself — can
// enroll DIRECTLY with lcm. The single-use join token is the sole credential
// (verified + burned via auth); lcm presents its own self-issued SVID as the
// server certificate, which the client pins against the mesh bundle. The
// workload's private key never leaves it (only a CSR is sent).
func (a *App) startEnrollListener(addr string) error {
	if a.Enroll == nil || a.selfIdentity == nil {
		return errors.New("app: enroll listener needs Enroll and self identity")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/lcm/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var in struct {
			SpiffeID        string `json:"spiffe_id"`
			CSRPEM          string `json:"csr_pem"`
			EnrollmentToken string `json:"enrollment_token"`
		}
		if derr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); derr != nil || in.SpiffeID == "" {
			http.Error(w, `{"reason":"validation_failed"}`, http.StatusUnprocessableEntity)
			return
		}
		if in.EnrollmentToken == "" {
			http.Error(w, `{"reason":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		res, eerr := a.Enroll.Enroll(r.Context(), authz.ServiceSubjects("", in.SpiffeID),
			enroll.EnrollInput{SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM, EnrollmentToken: in.EnrollmentToken})
		if eerr != nil {
			http.Error(w, `{"reason":"forbidden"}`, http.StatusForbidden)
			return
		}
		if res.Status != "issued" || res.Bundle == nil {
			http.Error(w, `{"reason":"pending"}`, http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": res.Bundle.CertPEM, "chain_pem": res.Bundle.ChainPEM, "bundle_pem": res.Bundle.BundlePEM,
		})
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.NoClientCert,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return a.selfIdentity.Credential()
			},
		},
	}
	a.AddCloser(func() { _ = srv.Close() })
	a.AddWorker(func(ctx context.Context) {
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		a.Log.Info("enroll listener (server-auth only) listening", "addr", addr)
		if serr := srv.ServeTLS(ln, "", ""); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			a.Log.Error("enroll listener stopped", "err", serr)
		}
	})
	return nil
}
