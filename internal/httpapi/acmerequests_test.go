package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// POST /certificates/acme refuses bad domains synchronously (422 naming the
// domain), records an accepted order as a generic request (202 with its
// request_id) and ends that request failed with the order's reason.
func TestACMEOrderRecordedAsRequest(t *testing.T) {
	f := newAPI(t)
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"le","type":"acme","trust_domain":"example.org",`+
		`"settings":{"directory":"https://127.0.0.1:1/dir","email":"ops@example.org","dns_provider":"cloudflare","zone_id":"z"}}`)
	mustStatus(t, w, http.StatusCreated)
	issuerID, _ := jsonBody(t, w)["id"].(string)

	w = f.req(t, "POST", Prefix+"/certificates/acme", "admin", `{"issuer_id":"`+issuerID+`","domains":["*.server-lab.eu","test.server-lab.eu"]}`)
	mustStatus(t, w, http.StatusUnprocessableEntity)
	if !strings.Contains(w.Body.String(), "test.server-lab.eu") || !strings.Contains(w.Body.String(), "domains") {
		t.Fatalf("400 body = %s", w.Body.String())
	}
	w = f.req(t, "POST", Prefix+"/certificates/acme", "admin", `{"issuer_id":"`+issuerID+`","domains":["*.server.-lab.eu"]}`)
	mustStatus(t, w, http.StatusUnprocessableEntity)
	if n := len(f.mem.Requests); n != 0 {
		t.Fatalf("%d requests recorded for refused orders", n)
	}

	// The provider cannot be built (no api_token), so the order fails in the
	// background without a network call.
	w = f.req(t, "POST", Prefix+"/certificates/acme", "admin", `{"issuer_id":"`+issuerID+`","domains":["WWW.example.org"]}`)
	mustStatus(t, w, http.StatusAccepted)
	body := jsonBody(t, w)
	reqID, _ := body["request_id"].(string)
	if body["status"] != "processing" || reqID == "" {
		t.Fatalf("202 body = %v", body)
	}
	if d, _ := body["domains"].([]any); len(d) != 1 || d[0] != "www.example.org" {
		t.Fatalf("domains = %v", body["domains"])
	}

	var got map[string]any
	for i := 0; i < 300; i++ {
		rw := f.req(t, "GET", Prefix+"/requests/"+reqID, "admin", "")
		mustStatus(t, rw, http.StatusOK)
		got = jsonBody(t, rw)
		if got["status"] != "processing" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got["status"] != "failed" || got["kind"] != "generic" || got["reason"] == "" || got["reason"] == nil {
		t.Fatalf("request = %v", got)
	}

	lw := f.req(t, "GET", Prefix+"/requests?status=failed", "admin", "")
	mustStatus(t, lw, http.StatusOK)
	if items, _ := jsonBody(t, lw)["items"].([]any); len(items) != 1 {
		t.Fatalf("failed listing = %s", lw.Body.String())
	}
	aw := f.req(t, "POST", Prefix+"/requests/"+reqID+"/approve", "admin", `{}`)
	mustStatus(t, aw, http.StatusConflict)
}
