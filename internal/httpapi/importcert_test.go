package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// importPair is a self-signed leaf for www.example.com valid until notAfter
// and its PKCS#8 key, as JSON-safe PEM strings.
func importPair(t *testing.T, serial int64, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func importBody(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// POST /certificates/import records the certificate (201) and reports whether
// a renewal is scheduled, started now (already due) or off; refusals are 422
// naming the field, a caller without use on the issuer gets 403.
func TestImportCertificateRoute(t *testing.T) {
	f := newAPI(t)
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"le","type":"acme","trust_domain":"*",`+
		`"settings":{"directory":"https://127.0.0.1:1/dir","email":"ops@example.org","dns_provider":"manual"}}`)
	mustStatus(t, w, http.StatusCreated)
	issuerID, _ := jsonBody(t, w)["id"].(string)

	cert, key := importPair(t, 11, time.Now().Add(80*24*time.Hour))
	w = f.req(t, "POST", Prefix+"/certificates/import", "admin", importBody(t, map[string]any{"issuer_id": issuerID, "cert_pem": cert, "key_pem": key}))
	mustStatus(t, w, http.StatusCreated)
	body := jsonBody(t, w)
	c, _ := body["certificate"].(map[string]any)
	if body["renewal"] != "scheduled" || c["kind"] != "generic" || c["auto_renew"] != true || c["has_key"] != true || c["issuer_id"] != issuerID {
		t.Fatalf("201 body = %v", body)
	}
	if _, leaked := c["key_pem"]; leaked {
		t.Fatal("key returned by the import")
	}

	// Already due: a renewal starts in the background (it fails here: the
	// directory is unreachable; the import itself stands).
	cert, key = importPair(t, 12, time.Now().Add(5*24*time.Hour))
	w = f.req(t, "POST", Prefix+"/certificates/import", "admin", importBody(t, map[string]any{"issuer_id": issuerID, "cert_pem": cert, "key_pem": key}))
	mustStatus(t, w, http.StatusCreated)
	if jsonBody(t, w)["renewal"] != "started" {
		t.Fatalf("due import = %s", w.Body.String())
	}
	cert, key = importPair(t, 13, time.Now().Add(5*24*time.Hour))
	w = f.req(t, "POST", Prefix+"/certificates/import", "admin", importBody(t, map[string]any{"issuer_id": issuerID, "cert_pem": cert, "key_pem": key, "auto_renew": false}))
	mustStatus(t, w, http.StatusCreated)
	if jsonBody(t, w)["renewal"] != "off" {
		t.Fatalf("auto_renew off = %s", w.Body.String())
	}

	// Wrong key: 422 naming the field, nothing stored.
	cert, _ = importPair(t, 14, time.Now().Add(80*24*time.Hour))
	_, other := importPair(t, 15, time.Now().Add(80*24*time.Hour))
	w = f.req(t, "POST", Prefix+"/certificates/import", "admin", importBody(t, map[string]any{"issuer_id": issuerID, "cert_pem": cert, "key_pem": other}))
	mustStatus(t, w, http.StatusUnprocessableEntity)
	if d, _ := jsonBody(t, w)["detail"].(map[string]any); d["field"] != "key" {
		t.Fatalf("422 body = %s", w.Body.String())
	}
	// Unknown fields are refused; bob holds no use on the issuer.
	w = f.req(t, "POST", Prefix+"/certificates/import", "admin", `{"issuer_id":"x","cert_pem":"","key_pem":"","extra":1}`)
	mustStatus(t, w, http.StatusBadRequest)
	cert, key = importPair(t, 16, time.Now().Add(80*24*time.Hour))
	w = f.req(t, "POST", Prefix+"/certificates/import", "bob", importBody(t, map[string]any{"issuer_id": issuerID, "cert_pem": cert, "key_pem": key}))
	mustStatus(t, w, http.StatusForbidden)
}
