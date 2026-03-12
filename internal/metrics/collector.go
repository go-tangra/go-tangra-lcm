package metrics

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonMetrics "github.com/go-tangra/go-tangra-common/metrics"
)

const namespace = "tangra"
const subsystem = "lcm"

// Collector holds all Prometheus metrics for the lcm module.
type Collector struct {
	log    *log.Helper
	server *commonMetrics.MetricsServer

	// mTLS certificate metrics
	MtlsCertificatesByStatus *prometheus.GaugeVec
	MtlsCertificatesByType   *prometheus.GaugeVec

	// Issued certificate metrics
	IssuedCertificatesByStatus *prometheus.GaugeVec

	// Client metrics
	ClientsByStatus *prometheus.GaugeVec

	// Issuer metrics
	IssuersByStatus *prometheus.GaugeVec

	// gRPC request metrics
	RequestDuration *prometheus.HistogramVec
	RequestsTotal   *prometheus.CounterVec
}

// NewCollector creates and registers all lcm Prometheus metrics.
func NewCollector(ctx *bootstrap.Context) *Collector {
	c := &Collector{
		log: ctx.NewLoggerHelper("lcm/metrics"),

		MtlsCertificatesByStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "mtls_certificates_by_status",
			Help:      "Number of mTLS certificates by status.",
		}, []string{"status"}),

		MtlsCertificatesByType: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "mtls_certificates_by_type",
			Help:      "Number of mTLS certificates by type.",
		}, []string{"cert_type"}),

		IssuedCertificatesByStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "issued_certificates_by_status",
			Help:      "Number of issued certificates by status.",
		}, []string{"status"}),

		ClientsByStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "clients_by_status",
			Help:      "Number of LCM clients by status.",
		}, []string{"status"}),

		IssuersByStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "issuers_by_status",
			Help:      "Number of issuers by status.",
		}, []string{"status"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "Histogram of gRPC request durations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method"}),

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_requests_total",
			Help:      "Total number of gRPC requests by method and status.",
		}, []string{"method", "status"}),
	}

	prometheus.MustRegister(
		c.MtlsCertificatesByStatus,
		c.MtlsCertificatesByType,
		c.IssuedCertificatesByStatus,
		c.ClientsByStatus,
		c.IssuersByStatus,
		c.RequestDuration,
		c.RequestsTotal,
	)

	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		addr = ":9110"
	}
	c.server = commonMetrics.NewMetricsServer(addr, nil, ctx.GetLogger())

	go func() {
		if err := c.server.Start(); err != nil {
			c.log.Errorf("Metrics server failed: %v", err)
		}
	}()

	return c
}

// Middleware returns a Kratos middleware that records gRPC request metrics.
func (c *Collector) Middleware() middleware.Middleware {
	return commonMetrics.NewServerMiddleware(c.RequestDuration, c.RequestsTotal)
}

// Stop shuts down the metrics HTTP server.
func (c *Collector) Stop(ctx context.Context) {
	if c.server != nil {
		c.server.Stop(ctx)
	}
}

// --- mTLS Certificate helpers ---

// MtlsCertificateCreated increments counters for a newly created mTLS certificate.
func (c *Collector) MtlsCertificateCreated(status, certType string) {
	c.MtlsCertificatesByStatus.WithLabelValues(status).Inc()
	c.MtlsCertificatesByType.WithLabelValues(certType).Inc()
}

// MtlsCertificateDeleted decrements counters for a deleted mTLS certificate.
func (c *Collector) MtlsCertificateDeleted(status, certType string) {
	c.MtlsCertificatesByStatus.WithLabelValues(status).Dec()
	c.MtlsCertificatesByType.WithLabelValues(certType).Dec()
}

// MtlsCertificateStatusChanged adjusts the status gauge when a certificate's status changes.
func (c *Collector) MtlsCertificateStatusChanged(oldStatus, newStatus string) {
	c.MtlsCertificatesByStatus.WithLabelValues(oldStatus).Dec()
	c.MtlsCertificatesByStatus.WithLabelValues(newStatus).Inc()
}

// --- Issued Certificate helpers ---

// IssuedCertificateCreated increments the issued certificate counter for the given status.
func (c *Collector) IssuedCertificateCreated(status string) {
	c.IssuedCertificatesByStatus.WithLabelValues(status).Inc()
}

// IssuedCertificateDeleted decrements the issued certificate counter for the given status.
func (c *Collector) IssuedCertificateDeleted(status string) {
	c.IssuedCertificatesByStatus.WithLabelValues(status).Dec()
}

// IssuedCertificateStatusChanged adjusts the status gauge when an issued certificate's status changes.
func (c *Collector) IssuedCertificateStatusChanged(oldStatus, newStatus string) {
	c.IssuedCertificatesByStatus.WithLabelValues(oldStatus).Dec()
	c.IssuedCertificatesByStatus.WithLabelValues(newStatus).Inc()
}

// --- Client helpers ---

// ClientCreated increments the client counter for the given status.
func (c *Collector) ClientCreated(status string) {
	c.ClientsByStatus.WithLabelValues(status).Inc()
}

// ClientDeleted decrements the client counter for the given status.
func (c *Collector) ClientDeleted(status string) {
	c.ClientsByStatus.WithLabelValues(status).Dec()
}

// ClientStatusChanged adjusts the status gauge when a client's status changes.
func (c *Collector) ClientStatusChanged(oldStatus, newStatus string) {
	c.ClientsByStatus.WithLabelValues(oldStatus).Dec()
	c.ClientsByStatus.WithLabelValues(newStatus).Inc()
}

// --- Issuer helpers ---

// IssuerCreated increments the issuer counter for the given status.
func (c *Collector) IssuerCreated(status string) {
	c.IssuersByStatus.WithLabelValues(status).Inc()
}

// IssuerDeleted decrements the issuer counter for the given status.
func (c *Collector) IssuerDeleted(status string) {
	c.IssuersByStatus.WithLabelValues(status).Dec()
}

// IssuerStatusChanged adjusts the status gauge when an issuer's status changes.
func (c *Collector) IssuerStatusChanged(oldStatus, newStatus string) {
	c.IssuersByStatus.WithLabelValues(oldStatus).Dec()
	c.IssuersByStatus.WithLabelValues(newStatus).Inc()
}
