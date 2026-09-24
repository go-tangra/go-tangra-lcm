// Package revoke serves the trust bundle (roots) and the revocation
// distribution for each trust domain: a revocation feed the auth service's
// RevocationChecker polls and a signed CRL, so verifiers drop a revoked SVID
// within the platform's revocation-propagation window (SR-006).
package revoke

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Repo is the persistence revoke reads.
type Repo interface {
	CAByState(ctx context.Context, tenantID, trustDomain, state string) (store.CA, error)
	ListRevocations(ctx context.Context, tenantID string, cursor time.Time, limit int) ([]store.Revocation, error)
}

// Service serves trust bundles, the revocation feed and CRLs.
type Service struct {
	repo Repo
	ca   *ca.Authority
	now  func() time.Time
}

// New builds the service.
func New(repo Repo, authority *ca.Authority, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{repo: repo, ca: authority, now: clock}
}

// TrustBundle returns the roots for a trust domain (PEM).
func (s *Service) TrustBundle(ctx context.Context, tenantID, trustDomain string) (string, error) {
	return s.ca.Bundle(ctx, tenantID, trustDomain)
}

// RevocationView is one revoked serial in the feed.
type RevocationView struct {
	Serial    string    `json:"serial"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Feed returns the revocation feed (newest first).
func (s *Service) Feed(ctx context.Context, tenantID string, cursor time.Time, limit int) ([]RevocationView, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	if cursor.IsZero() {
		cursor = s.now()
	}
	rows, err := s.repo.ListRevocations(ctx, tenantID, cursor, limit)
	if err != nil {
		return nil, err
	}
	out := make([]RevocationView, 0, len(rows))
	for _, r := range rows {
		out = append(out, RevocationView{Serial: r.Serial, Reason: r.Reason, RevokedAt: r.RevokedAt})
	}
	return out, nil
}

// CRL builds a signed CRL (PEM) for a trust domain from its revocations,
// signed by the trust domain's active CA.
func (s *Service) CRL(ctx context.Context, tenantID, trustDomain string) ([]byte, error) {
	caRow, err := s.repo.CAByState(ctx, tenantID, trustDomain, "active")
	if err != nil {
		return nil, err
	}
	signer, caCert, err := s.ca.Signer(ctx, caRow)
	if err != nil {
		return nil, err
	}
	// Page through all revocations for the tenant.
	var entries []x509.RevocationListEntry
	cursor := s.now()
	for {
		rows, err := s.repo.ListRevocations(ctx, tenantID, cursor, 1000)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			serial, ok := new(big.Int).SetString(r.Serial, 10)
			if !ok {
				continue
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: r.RevokedAt.UTC()})
			cursor = r.RevokedAt
		}
		if len(rows) < 1000 {
			break
		}
	}
	now := s.now().UTC()
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
