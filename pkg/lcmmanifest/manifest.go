// Package lcmmanifest declares what the lcm module registers with the
// application gateway: routes derived from the embedded OpenAPI document, the
// API permissions, the CASL abilities the shell derives from them and the
// navigation entries (contracts/manifest.md). The lcm.v1 gRPC surface is
// service-to-service and not proxied. Public so contract tests and the gateway
// can validate it.
package lcmmanifest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra-lcm/v4/api/openapi"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
)

// Module is the registered module name.
const (
	Module      = "lcm"
	DisplayName = "Certificates"
	Version     = "1.0.0"
	// RemotePrefix is where the module serves its federated remote assets;
	// it is reached through the gateway relay (/m/lcm/…) and is NOT owned as
	// a gateway prefix (that would conflict with any other UI module).
	RemotePrefix = "/ui"
)

// OpenAPI operation extensions read by the builder.
const (
	PermissionExtension    = "x-freya-permission"
	PublicExtension        = "x-freya-public"
	BodyLimitExtension     = "x-freya-max-body-bytes"
	ClientAddressExtension = "x-freya-client-address"
	TimeoutExtension       = "x-freya-timeout-seconds"
)

// Permissions the module registers (granted to built-in roles by the auth service).
var Permissions = []gatewayclient.Permission{
	{Resource: "certificates", Action: "read", Description: "List and read certificates/SVIDs the caller is granted"},
	{Resource: "certificates", Action: "issue", Description: "Issue certificates/SVIDs for identities the caller may use"},
	{Resource: "certificates", Action: "manage", Description: "Renew, deploy, update and delete certificates the caller is granted"},
	{Resource: "certificates", Action: "revoke", Description: "Revoke certificates the caller is granted"},
	{Resource: "issuers", Action: "read", Description: "List and read issuers (credentials redacted)"},
	{Resource: "issuers", Action: "manage", Description: "Create, change and delete issuers and their CAs"},
	{Resource: "enrollment", Action: "enroll", Description: "Enroll a workload for an SVID with a platform identity or enrollment token"},
	{Resource: "jobs", Action: "read", Description: "List and read certificate jobs"},
	{Resource: "jobs", Action: "manage", Description: "Cancel and retry certificate jobs"},
	{Resource: "permissions", Action: "manage", Description: "Grant and revoke access on certificates and issuers the caller may share"},
	{Resource: "secrets", Action: "manage", Description: "Create, rotate and delete tenant secrets (ACME/DNS credentials)"},
	{Resource: "webhooks", Action: "manage", Description: "Create and delete outbound webhook endpoints"},
	{Resource: "backup", Action: "manage", Description: "Export and import tenant backups (bulk disclosure with credentials on request)"},
	{Resource: "stats", Action: "read", Description: "Read statistics, health and the audit trail"},
}

// Grants maps built-in role slugs to the permission references they hold; the
// auth service seeds them on permission registration.
var Grants = map[string][]string{
	"owner":    PermissionRefs(),
	"admin":    PermissionRefs(),
	"member":   {"certificates:read", "certificates:issue", "issuers:read", "enrollment:enroll", "jobs:read"},
	"auditor":  {"stats:read", "certificates:read"},
	"operator": {"stats:read", "certificates:read", "certificates:manage", "certificates:revoke", "jobs:read", "jobs:manage"},
}

// Methods proxied by the gateway: none (lcm.v1 is called service to service).
var Methods []gatewayclient.Method

// Abilities are the CASL rules bound to the permissions.
var Abilities = []gatewayclient.Ability{
	{Action: []string{"read", "create", "update", "delete", "share", "use"}, Subject: []string{"Certificate"}, Requires: "certificates:read"},
	{Action: []string{"read", "create", "update", "delete", "share"}, Subject: []string{"Issuer"}, Requires: "issuers:read"},
	{Action: []string{"enroll"}, Subject: []string{"Enrollment"}, Requires: "enrollment:enroll"},
	{Action: []string{"read", "manage"}, Subject: []string{"CertificateJob"}, Requires: "jobs:read"},
	{Action: []string{"manage"}, Subject: []string{"LcmGrant"}, Requires: "permissions:manage"},
	{Action: []string{"manage"}, Subject: []string{"TenantSecret"}, Requires: "secrets:manage"},
	{Action: []string{"manage"}, Subject: []string{"Webhook"}, Requires: "webhooks:manage"},
	{Action: []string{"manage"}, Subject: []string{"LcmBackup"}, Requires: "backup:manage"},
	{Action: []string{"read"}, Subject: []string{"LcmStats", "LcmAudit"}, Requires: "stats:read"},
}

// Nav lists the navigation contributions (the shell groups them under the module).
var Nav = []gatewayclient.NavEntry{
	{Title: "Dashboard", Path: "/lcm", Icon: "mdi-view-dashboard-outline", Order: 300, Requires: "stats:read"},
	{Title: "Certificates", Path: "/lcm/certificates", Icon: "mdi-certificate-outline", Order: 310, Requires: "certificates:read"},
	{Title: "Issuers", Path: "/lcm/issuers", Icon: "mdi-shield-key-outline", Order: 320, Requires: "issuers:read"},
	{Title: "Requests", Path: "/lcm/requests", Icon: "mdi-clipboard-check-outline", Order: 330, Requires: "jobs:read"},
	{Title: "Permissions", Path: "/lcm/permissions", Icon: "mdi-shield-account-outline", Order: 340, Requires: "permissions:manage"},
	{Title: "Secrets", Path: "/lcm/secrets", Icon: "mdi-key-outline", Order: 350, Requires: "secrets:manage"},
	{Title: "Audit", Path: "/lcm/audit", Icon: "mdi-history", Order: 360, Requires: "stats:read"},
}

// PermissionRefs lists "resource:action" for every declared permission.
func PermissionRefs() []string {
	out := make([]string, 0, len(Permissions))
	for _, p := range Permissions {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}

// Routes derives the gateway routes from the OpenAPI document: every operation
// carries x-freya-permission (one of Permissions); there is no public route.
// x-freya-max-body-bytes and x-freya-timeout-seconds map to the route fields.
func Routes(doc *openapi3.T) ([]gatewayclient.Route, error) {
	known := map[string]bool{}
	for _, p := range PermissionRefs() {
		known[p] = true
	}
	var routes []gatewayclient.Route
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			r := gatewayclient.Route{Method: strings.ToUpper(m), Path: p}
			perm, _ := op.Extensions[PermissionExtension].(string)
			public, _ := op.Extensions[PublicExtension].(bool)
			switch {
			case public:
				r.Public = true
			case perm == "":
				return nil, fmt.Errorf("lcmmanifest: %s %s declares no permission", r.Method, p)
			case !known[perm]:
				return nil, fmt.Errorf("lcmmanifest: %s %s uses undeclared permission %q", r.Method, p, perm)
			default:
				r.Permission = perm
			}
			if v, ok := op.Extensions[BodyLimitExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 {
					return nil, fmt.Errorf("lcmmanifest: %s %s has a bad body limit", r.Method, p)
				}
				r.MaxBodyBytes = uint64(n)
			}
			if v, ok := op.Extensions[ClientAddressExtension].(bool); ok && v {
				r.ClientAddress = true
			}
			if v, ok := op.Extensions[TimeoutExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 || n > 600 {
					return nil, fmt.Errorf("lcmmanifest: %s %s has a bad timeout", r.Method, p)
				}
				r.Timeout = time.Duration(n) * time.Second
			}
			routes = append(routes, r)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path })
	return routes, nil
}

// Load parses the embedded document.
func Load() (*openapi3.T, error) {
	return openapi3.NewLoader().LoadFromData(openapi.LCM)
}

// Manifest builds the gateway manifest from the embedded OpenAPI document.
func Manifest() (gatewayclient.Manifest, error) {
	doc, err := Load()
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	routes, err := Routes(doc)
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	return gatewayclient.Manifest{
		Module: Module, DisplayName: DisplayName, Version: Version,
		Prefixes:    []string{"/api/lcm"},
		Routes:      routes,
		Methods:     Methods,
		Permissions: Permissions,
		Abilities:   Abilities,
		Exposes:     []string{"./routes", "./nav", "./header"},
		Nav:         Nav,
	}, nil
}
