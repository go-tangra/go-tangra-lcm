package httpapi

import (
	"net/http"
	"testing"
)

// TestHandlerErrorPaths drives representative service-error branches through
// the handlers (404 masking, conflicts, validation and forbidden checks).
func TestHandlerErrorPaths(t *testing.T) {
	f := newAPI(t)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)

	unknown := "44444444-4444-7444-8444-444444444444"

	// Unknown single-resource reads are masked as not found.
	mustStatus(t, f.req(t, "GET", Prefix+"/issuers/"+unknown, "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+unknown, "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+unknown+"/download", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/requests/"+unknown, "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/jobs/"+unknown, "admin", ""), http.StatusNotFound)

	// Operating on unknown resources.
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+unknown+"/renew", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+unknown+"/revoke", "admin", `{"reason":"x"}`), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+unknown+"/remove", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers/"+unknown+"/remove", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/requests/"+unknown+"/approve", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/requests/"+unknown+"/reject", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/jobs/"+unknown+"/cancel", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/jobs/"+unknown+"/retry", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/secrets/"+unknown+"/remove", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/webhooks/"+unknown+"/remove", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "POST", Prefix+"/grants/"+unknown+"/revoke", "admin", ""), http.StatusNotFound)

	// access/check for an unknown resource is answered (allowed:false), not an error.
	mustStatus(t, f.req(t, "GET", Prefix+"/access/check?resource_type=certificate&resource_id="+unknown+"&action=read", "admin", ""), http.StatusOK)

	// Duplicate secret and webhook names conflict.
	mustStatus(t, f.req(t, "POST", Prefix+"/secrets", "admin", `{"name":"dup","kind":"acme_account","value":{"k":"v"}}`), http.StatusCreated)
	mustStatus(t, f.req(t, "POST", Prefix+"/secrets", "admin", `{"name":"dup","kind":"acme_account","value":{"k":"v"}}`), http.StatusConflict)
	mustStatus(t, f.req(t, "POST", Prefix+"/webhooks", "admin", `{"name":"dup","url":"https://e.com/h","event_types":["certificate.issued"],"secret":"s3cr3t-value-abcdefabcdef"}`), http.StatusCreated)
	mustStatus(t, f.req(t, "POST", Prefix+"/webhooks", "admin", `{"name":"dup","url":"https://e.com/h","event_types":["certificate.issued"],"secret":"s3cr3t-value-abcdefabcdef"}`), http.StatusConflict)

	// A caller with no grants cannot list grants on a resource they cannot see.
	mustStatus(t, f.req(t, "GET", Prefix+"/grants?resource_type=certificate&resource_id="+unknown, "bob", ""), http.StatusNotFound)
}
