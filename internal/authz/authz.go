// Package authz decides access to certificates and issuers with Zanzibar-style
// relation tuples: grants of owner/editor/viewer/sharer on a resource to a
// user, a role or the whole tenant, optionally expiring. The `use` action
// (issuance/enrollment/renew) belongs to owner, editor and sharer. Tenant
// administrators (the built-in owner/admin roles) hold owner on everything of
// their tenant. This package is pure decision logic: it records no audit;
// callers audit the outcomes they act on.
package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Relations and actions.
const (
	Owner  = "owner"
	Editor = "editor"
	Viewer = "viewer"
	Sharer = "sharer"

	Read   = "read"
	Write  = "write"
	Delete = "delete"
	Share  = "share"
	Use    = "use"
)

// Resource and subject types.
const (
	Certificate = "certificate"
	Issuer      = "issuer"

	SubjectUser   = "user"
	SubjectRole   = "role"
	SubjectTenant = "tenant"
)

// AdminRoles hold owner implicitly.
var AdminRoles = []string{"owner", "admin"}

// Errors.
var (
	ErrForbidden = errors.New("authz: forbidden")
	ErrNotFound  = errors.New("authz: resource not found")
	ErrInput     = errors.New("authz: invalid input")
	// ErrAboveGranter refuses a grant above the granter's own relation.
	ErrAboveGranter = fmt.Errorf("%w: relation_above_granter", ErrForbidden)
)

// Store is the persistence authz reads and writes (repo.Store satisfies it).
type Store interface {
	GetCertificate(ctx context.Context, tenantID, id string) (store.IssuedCertificate, error)
	GetIssuer(ctx context.Context, tenantID, id string) (store.Issuer, error)
	UpsertGrant(ctx context.Context, g store.Grant) (store.Grant, error)
	GetGrant(ctx context.Context, tenantID, id string) (store.Grant, error)
	DeleteGrant(ctx context.Context, tenantID, id string) error
	GrantsOnResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]store.Grant, error)
	GrantsForSubjects(ctx context.Context, tenantID, userID string, roles []string, now time.Time) ([]store.Grant, error)
	DeleteGrantsOfResource(ctx context.Context, tenantID, resourceType, resourceID string) error
}

// Subjects is the caller as seen by the grant tables. Service callers act for
// a tenant with no user id and no roles: only tenant-wide grants apply.
type Subjects struct {
	TenantID string
	UserID   string
	Roles    []string
	Service  string // SPIFFE id of a service caller ("" for people)
}

// SubjectsOf derives the subjects from a verified platform identity (the roles
// are effective: direct and through groups).
func SubjectsOf(id authclient.Identity) Subjects {
	return Subjects{TenantID: id.TenantID, UserID: id.UserID, Roles: append([]string(nil), id.Roles...)}
}

// ServiceSubjects is a module acting for a tenant.
func ServiceSubjects(tenantID, spiffeID string) Subjects {
	return Subjects{TenantID: tenantID, Service: spiffeID}
}

// ActorKind reports whether the caller is a service or a user (for audit).
func (s Subjects) ActorKind() string {
	if s.Service != "" {
		return "service"
	}
	return "user"
}

// ActorID is the user id or the service id.
func (s Subjects) ActorID() string {
	if s.Service != "" {
		return s.Service
	}
	return s.UserID
}

// IsAdmin reports whether the subjects hold a tenant-administrator role.
func (s Subjects) IsAdmin() bool {
	for _, r := range s.Roles {
		for _, a := range AdminRoles {
			if r == a {
				return true
			}
		}
	}
	return false
}

// Permissions are the derived booleans of a relation set.
type Permissions struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	Delete bool `json:"delete"`
	Share  bool `json:"share"`
	Use    bool `json:"use"`
}

// Has reports one permission.
func (p Permissions) Has(perm string) bool {
	switch perm {
	case Read:
		return p.Read
	case Write:
		return p.Write
	case Delete:
		return p.Delete
	case Share:
		return p.Share
	case Use:
		return p.Use
	}
	return false
}

// Of returns the permissions a relation carries. owner=all; editor=read,write,
// use; viewer=read; sharer=read,share,use.
func Of(relation string) Permissions {
	switch relation {
	case Owner:
		return Permissions{Read: true, Write: true, Delete: true, Share: true, Use: true}
	case Editor:
		return Permissions{Read: true, Write: true, Use: true}
	case Viewer:
		return Permissions{Read: true}
	case Sharer:
		return Permissions{Read: true, Share: true, Use: true}
	}
	return Permissions{}
}

// rank orders relations for "strongest" reporting and granter bounds.
func rank(relation string) int {
	switch relation {
	case Owner:
		return 4
	case Editor:
		return 3
	case Sharer:
		return 2
	case Viewer:
		return 1
	}
	return 0
}

// ValidRelation / ValidPermission / ValidResourceType / ValidSubjectType.
func ValidRelation(r string) bool { return rank(r) > 0 }
func ValidPermission(p string) bool {
	return p == Read || p == Write || p == Delete || p == Share || p == Use
}
func ValidResourceType(t string) bool { return t == Certificate || t == Issuer }
func ValidSubjectType(t string) bool {
	return t == SubjectUser || t == SubjectRole || t == SubjectTenant
}

// Authorizer evaluates and manages grants over a Store.
type Authorizer struct {
	st  Store
	now func() time.Time
}

// New wires the evaluator.
func New(st Store) *Authorizer {
	return &Authorizer{st: st, now: time.Now}
}

// SetClock injects the clock (tests).
func (a *Authorizer) SetClock(now func() time.Time) { a.now = now }

// locate verifies the (already validated) resource type/id exists in the
// caller's tenant; anything outside is ErrNotFound (masking existence).
func (a *Authorizer) locate(ctx context.Context, tenantID, resourceType, resourceID string) error {
	var err error
	if resourceType == Certificate {
		_, err = a.st.GetCertificate(ctx, tenantID, resourceID)
	} else {
		_, err = a.st.GetIssuer(ctx, tenantID, resourceID)
	}
	return notFound(err)
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// matches reports whether a grant applies to the subjects at now.
func matches(g store.Grant, s Subjects, now time.Time) bool {
	if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
		return false
	}
	switch g.SubjectType {
	case SubjectUser:
		return s.UserID != "" && g.SubjectID == s.UserID
	case SubjectRole:
		for _, r := range s.Roles {
			if r == g.SubjectID {
				return true
			}
		}
		return false
	}
	return g.SubjectType == SubjectTenant
}

func union(a, b Permissions) Permissions {
	return Permissions{Read: a.Read || b.Read, Write: a.Write || b.Write, Delete: a.Delete || b.Delete, Share: a.Share || b.Share, Use: a.Use || b.Use}
}

// decide computes the effective permissions, strongest relation and the
// contributing grants for subjects from the grants on the resource.
// Administrators hold owner implicitly.
func (a *Authorizer) decide(s Subjects, grants []store.Grant) (Permissions, string, []store.Grant) {
	var perms Permissions
	relation := ""
	var sources []store.Grant
	if s.IsAdmin() {
		perms = Of(Owner)
		relation = Owner
	}
	now := a.now()
	for _, g := range grants {
		if !matches(g, s, now) {
			continue
		}
		perms = union(perms, Of(g.Relation))
		if rank(g.Relation) > rank(relation) {
			relation = g.Relation
		}
		sources = append(sources, g)
	}
	return perms, relation, sources
}

// resolve locates the resource then evaluates the subjects' effective relation
// on it. A resource outside the tenant is ErrNotFound.
func (a *Authorizer) resolve(ctx context.Context, s Subjects, resourceType, resourceID string) (Permissions, string, []store.Grant, error) {
	if err := a.locate(ctx, s.TenantID, resourceType, resourceID); err != nil {
		return Permissions{}, "", nil, err
	}
	grants, err := a.st.GrantsOnResource(ctx, s.TenantID, resourceType, resourceID)
	if err != nil {
		return Permissions{}, "", nil, err
	}
	perms, relation, sources := a.decide(s, grants)
	return perms, relation, sources, nil
}

// Check answers whether the subjects hold the action on the resource. It
// returns nil when allowed, ErrForbidden when not, ErrNotFound for a resource
// outside the tenant, and ErrInput for a bad resource type or action.
func (a *Authorizer) Check(ctx context.Context, s Subjects, resourceType, resourceID, action string) error {
	if !ValidResourceType(resourceType) || !ValidPermission(action) {
		return ErrInput
	}
	perms, _, _, err := a.resolve(ctx, s, resourceType, resourceID)
	if err != nil {
		return err
	}
	if !perms.Has(action) {
		return ErrForbidden
	}
	return nil
}

// Effective explains the subjects' permissions on a resource with the
// strongest relation held and every contributing grant.
func (a *Authorizer) Effective(ctx context.Context, s Subjects, resourceType, resourceID string) (Permissions, string, []store.Grant, error) {
	if !ValidResourceType(resourceType) {
		return Permissions{}, "", nil, ErrInput
	}
	return a.resolve(ctx, s, resourceType, resourceID)
}

// ListAccessibleIDs returns the ids of resourceType the subjects may read, or
// all=true for administrators (listing filter).
func (a *Authorizer) ListAccessibleIDs(ctx context.Context, s Subjects, resourceType string) (ids map[string]bool, all bool, err error) {
	if !ValidResourceType(resourceType) {
		return nil, false, ErrInput
	}
	if s.IsAdmin() {
		return nil, true, nil
	}
	grants, err := a.st.GrantsForSubjects(ctx, s.TenantID, s.UserID, s.Roles, a.now())
	if err != nil {
		return nil, false, err
	}
	ids = map[string]bool{}
	for _, g := range grants {
		if g.ResourceType == resourceType && Of(g.Relation).Read {
			ids[g.ResourceID] = true
		}
	}
	return ids, false, nil
}
