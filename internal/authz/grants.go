package authz

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/store"
)

// GrantInput is a grant request.
type GrantInput struct {
	ResourceType string
	ResourceID   string
	SubjectType  string
	SubjectID    string
	Relation     string
	ExpiresAt    *time.Time
}

// validate checks the shape of a grant request.
func (in GrantInput) validate(now time.Time) error {
	if !ValidResourceType(in.ResourceType) || !ValidSubjectType(in.SubjectType) || !ValidRelation(in.Relation) || in.ResourceID == "" {
		return ErrInput
	}
	switch in.SubjectType {
	case SubjectTenant:
		if in.SubjectID != "" {
			return ErrInput
		}
	default:
		if in.SubjectID == "" || len(in.SubjectID) > 128 {
			return ErrInput
		}
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return ErrInput
	}
	return nil
}

// Grant creates or replaces a grant. The granter needs share on the resource
// and may not hand out a relation above the strongest one they hold there.
func (a *Authorizer) Grant(ctx context.Context, s Subjects, in GrantInput) (store.Grant, error) {
	if err := in.validate(a.now()); err != nil {
		return store.Grant{}, err
	}
	perms, held, _, err := a.resolve(ctx, s, in.ResourceType, in.ResourceID)
	if err != nil {
		return store.Grant{}, err
	}
	if !perms.Share {
		return store.Grant{}, ErrForbidden
	}
	if rank(in.Relation) > rank(held) {
		return store.Grant{}, ErrAboveGranter
	}
	var by *string
	if s.UserID != "" {
		u := s.UserID
		by = &u
	}
	g, err := a.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: s.TenantID, ResourceType: in.ResourceType, ResourceID: in.ResourceID,
		SubjectType: in.SubjectType, SubjectID: in.SubjectID, Relation: in.Relation, GrantedBy: by, ExpiresAt: in.ExpiresAt})
	if err != nil {
		return store.Grant{}, err
	}
	return g, nil
}

// Revoke deletes a grant; the caller needs share on its resource.
func (a *Authorizer) Revoke(ctx context.Context, s Subjects, grantID string) error {
	g, err := a.st.GetGrant(ctx, s.TenantID, grantID)
	if err != nil {
		return notFound(err)
	}
	perms, _, _, err := a.resolve(ctx, s, g.ResourceType, g.ResourceID)
	if err != nil {
		return err
	}
	if !perms.Share {
		return ErrForbidden
	}
	if err := a.st.DeleteGrant(ctx, s.TenantID, grantID); err != nil {
		return notFound(err)
	}
	return nil
}

// GrantOwner records the creator-owner grant of a new resource. Service
// creators leave no grant: administrators hold owner implicitly.
func (a *Authorizer) GrantOwner(ctx context.Context, tenantID, resourceType, resourceID, userID string) error {
	if userID == "" {
		return nil
	}
	by := userID
	_, err := a.st.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tenantID, ResourceType: resourceType, ResourceID: resourceID,
		SubjectType: SubjectUser, SubjectID: userID, Relation: Owner, GrantedBy: &by})
	return err
}

// DropResource removes every grant of a deleted resource.
func (a *Authorizer) DropResource(ctx context.Context, tenantID, resourceType, resourceID string) error {
	return a.st.DeleteGrantsOfResource(ctx, tenantID, resourceType, resourceID)
}

// ListGrants returns every grant on a resource; the caller needs share (which
// tenant administrators hold implicitly). Unknown/cross-tenant resources are
// masked as ErrNotFound by resolve.
func (a *Authorizer) ListGrants(ctx context.Context, s Subjects, resourceType, resourceID string) ([]store.Grant, error) {
	perms, _, _, err := a.resolve(ctx, s, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if !perms.Share {
		return nil, ErrForbidden
	}
	return a.st.GrantsOnResource(ctx, s.TenantID, resourceType, resourceID)
}
