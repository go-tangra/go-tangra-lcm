// Package grpcapi serves lcm.v1 for other platform services and workload
// agents on the Freya mTLS channel: the caller is an authenticated service or
// workload (mTLS, policed by policy.yaml, SR-003) acting for the tenant named
// in the request; the tenant and actor are derived from the verified SPIFFE
// identity and the request. Nothing here is proxied by the gateway. Every
// call is audited with the service identity. The concrete SVID, Enrollment,
// Events and Agent servers are registered by the user-story phases.
package grpcapi

import (
	"context"
	"errors"
	"regexp"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/authn"
	lcmv1 "github.com/go-freya/freya/services/lcm/api/proto/lcm/v1"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/store"
	"github.com/go-freya/freya/services/lcm/internal/stream"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// callerFunc resolves the SPIFFE identity of a call (overridable in tests).
var callerFunc = func(ctx context.Context) (string, bool) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return "", false
	}
	return p.ID.String(), true
}

// ServiceCaller returns the SPIFFE identity of the calling service/workload.
func ServiceCaller(ctx context.Context) (string, bool) { return callerFunc(ctx) }

// caller returns the service subjects for the tenant named in the request; the
// tenant must be a uuid and the peer must present a SPIFFE identity.
func caller(ctx context.Context, tenantID string) (authz.Subjects, error) {
	id, ok := callerFunc(ctx)
	if !ok {
		return authz.Subjects{}, status.Error(codes.Unauthenticated, "service identity required")
	}
	if !uuidRE.MatchString(tenantID) {
		return authz.Subjects{}, status.Error(codes.InvalidArgument, "tenant_id must be a uuid")
	}
	return authz.ServiceSubjects(tenantID, id), nil
}

// grpcError maps a service error to a gRPC status.
func grpcError(err error) error {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, authz.ErrNotFound), errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, "not_found")
	case errors.Is(err, authz.ErrInput):
		return status.Error(codes.InvalidArgument, "invalid_argument")
	case errors.Is(err, csr.ErrTooLarge):
		return status.Error(codes.InvalidArgument, "too_large")
	case errors.Is(err, csr.ErrParse), errors.Is(err, csr.ErrSPIFFEID), errors.Is(err, csr.ErrWeakKey), errors.Is(err, csr.ErrSANs):
		return status.Error(codes.InvalidArgument, "invalid_argument")
	case errors.Is(err, store.ErrConflict):
		return status.Error(codes.AlreadyExists, "conflict")
	}
	return status.Error(codes.Unavailable, "temporarily_unavailable")
}

// Deps carries the services the lcm.v1 servers use.
type Deps struct {
	Issue  *issue.Service
	Enroll *enroll.Service
	CA     *ca.Authority
	Repo   Repo
	Hub    *stream.Hub
}

// Register registers the lcm.v1 servers on the gRPC server (SVID, Enrollment,
// Events, Agent). Callers are authenticated services/workloads policed by
// policy.yaml; nothing here is proxied by the gateway.
func Register(gs grpc.ServiceRegistrar, d Deps) {
	if d.Issue != nil {
		lcmv1.RegisterSVIDServer(gs, &SVIDServer{Svc: d.Issue, CA: d.CA, Repo: d.Repo})
		lcmv1.RegisterCertificatesServer(gs, &CertificatesServer{Svc: d.Issue})
	}
	if d.Enroll != nil {
		lcmv1.RegisterEnrollmentServer(gs, &EnrollmentServer{Svc: d.Enroll})
	}
	if d.Hub != nil {
		lcmv1.RegisterEventsServer(gs, &EventsServer{Hub: d.Hub})
		lcmv1.RegisterAgentServer(gs, &AgentServer{Hub: d.Hub})
	}
}
