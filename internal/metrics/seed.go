package metrics

import (
	"context"

	"github.com/go-tangra/go-tangra-lcm/internal/data"
)

// Seed loads initial gauge values from the database.
// Called once at startup so Prometheus has accurate values from the start.
func (c *Collector) Seed(ctx context.Context, statsRepo *data.StatisticsRepo) {
	c.log.Info("Seeding Prometheus metrics from database...")

	// Seed mTLS certificate stats
	certStats, err := statsRepo.GetCertificateStats(ctx, nil, 30)
	if err != nil {
		c.log.Errorf("Failed to seed mTLS certificate stats: %v", err)
	} else {
		c.MtlsCertificatesByStatus.WithLabelValues("active").Set(float64(certStats.ActiveCount))
		c.MtlsCertificatesByStatus.WithLabelValues("expired").Set(float64(certStats.ExpiredCount))
		c.MtlsCertificatesByStatus.WithLabelValues("revoked").Set(float64(certStats.RevokedCount))
		c.MtlsCertificatesByStatus.WithLabelValues("suspended").Set(float64(certStats.SuspendedCount))

		c.MtlsCertificatesByType.WithLabelValues("client").Set(float64(certStats.ClientCerts))
		c.MtlsCertificatesByType.WithLabelValues("internal").Set(float64(certStats.InternalCerts))
		c.MtlsCertificatesByType.WithLabelValues("ca").Set(float64(certStats.CaCerts))
	}

	// Seed issued certificate stats
	issuedStats, err := statsRepo.GetIssuedCertificateStats(ctx, nil, 30)
	if err != nil {
		c.log.Errorf("Failed to seed issued certificate stats: %v", err)
	} else {
		c.IssuedCertificatesByStatus.WithLabelValues("issued").Set(float64(issuedStats.ActiveCount))
		c.IssuedCertificatesByStatus.WithLabelValues("expired").Set(float64(issuedStats.ExpiredCount))
		c.IssuedCertificatesByStatus.WithLabelValues("revoked").Set(float64(issuedStats.RevokedCount))
		c.IssuedCertificatesByStatus.WithLabelValues("pending").Set(float64(issuedStats.PendingCount))
		c.IssuedCertificatesByStatus.WithLabelValues("processing").Set(float64(issuedStats.ProcessingCount))
		c.IssuedCertificatesByStatus.WithLabelValues("failed").Set(float64(issuedStats.FailedCount))
	}

	// Seed client stats
	clientStats, err := statsRepo.GetClientStats(ctx, nil)
	if err != nil {
		c.log.Errorf("Failed to seed client stats: %v", err)
	} else {
		for status, count := range clientStats.ByStatus {
			c.ClientsByStatus.WithLabelValues(status).Set(float64(count))
		}
	}

	// Seed issuer stats
	issuerStats, err := statsRepo.GetIssuerStats(ctx, nil)
	if err != nil {
		c.log.Errorf("Failed to seed issuer stats: %v", err)
	} else {
		c.IssuersByStatus.WithLabelValues("active").Set(float64(issuerStats.ActiveCount))
		c.IssuersByStatus.WithLabelValues("disabled").Set(float64(issuerStats.DisabledCount))
		c.IssuersByStatus.WithLabelValues("error").Set(float64(issuerStats.ErrorCount))
	}

	c.log.Info("Prometheus metrics seeded successfully")
}
