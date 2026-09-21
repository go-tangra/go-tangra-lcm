package app

import (
	"context"
	"strings"
	"time"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
)

// AuthPerms answers API permission questions through the auth service's
// Authorization/Check. A failed call is a "no".
type AuthPerms struct {
	Client authv1.AuthorizationClient
}

// Has implements httpapi.PermissionChecker.
func (p AuthPerms) Has(ctx context.Context, tenantID, userID, permission string) bool {
	resource, action, ok := strings.Cut(permission, ":")
	if !ok || p.Client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := p.Client.Check(ctx, &authv1.CheckRequest{TenantId: tenantID, UserId: userID, Resource: resource, Action: action})
	return err == nil && res.GetAllowed()
}
