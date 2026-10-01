package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/certinfo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const (
	detailsCertID = "44444444-4444-7444-8444-444444444444"
	detailsBadID  = "55555555-5555-7555-8555-555555555555"
)

// selfSignedPEM mints a certificate whose fields deliberately differ from the
// row columns the test stores next to it.
func selfSignedPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, _ := url.Parse("spiffe://example.org/decoded")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xbeef),
		Subject:      pkix.Name{CommonName: "decoded.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"decoded.example.org"},
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.10")},
		URIs:         []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertificateDetailsDecodedFromCertificate(t *testing.T) {
	f := newAPI(t)
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`)
	mustStatus(t, w, http.StatusCreated)
	issuerID, _ := jsonBody(t, w)["id"].(string)

	certNotAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	// The row columns disagree with the certificate on purpose: the response
	// must show what the certificate says.
	dbNotAfter := time.Now().Add(5 * 24 * time.Hour).UTC().Truncate(time.Second)
	row := store.IssuedCertificate{
		ID: detailsCertID, TenantID: apiTenant, IssuerID: issuerID, Kind: "svid", Serial: "db-serial",
		SpiffeID: "spiffe://example.org/column", Subject: "CN=column-subject", SANs: []byte(`["column.example.org"]`),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: dbNotAfter, FingerprintSHA256: "column-fp", Status: "active",
		CertPEM: selfSignedPEM(t, certNotAfter), KeySealed: []byte("sealed-key-material"), Owner: apiAdmin,
	}
	if err := f.mem.InsertCertificate(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	bad := row
	bad.ID, bad.Serial, bad.CertPEM = detailsBadID, "db-serial-2", "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"
	if err := f.mem.InsertCertificate(context.Background(), bad); err != nil {
		t.Fatal(err)
	}

	w = f.req(t, "GET", Prefix+"/certificates/"+detailsCertID+"/details", "admin", "")
	mustStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "sealed-key-material") || strings.Contains(w.Body.String(), "PRIVATE") || strings.Contains(w.Body.String(), "BEGIN") {
		t.Fatalf("response leaks stored material: %s", w.Body.String())
	}
	var res certinfo.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Details == nil {
		t.Fatalf("result %+v", res)
	}
	d := res.Details
	if !d.Validity.NotAfter.Equal(certNotAfter) || d.Validity.NotAfter.Equal(dbNotAfter) {
		t.Fatalf("not_after %v: want the certificate's %v, not the column's %v", d.Validity.NotAfter, certNotAfter, dbNotAfter)
	}
	if d.Subject.CN != "decoded.example.org" || d.Serial != "BE:EF" || d.Fingerprints.SHA256 == "column-fp" {
		t.Fatalf("details from columns? %+v", d)
	}
	if len(d.SANs.DNS) != 1 || d.SANs.DNS[0] != "decoded.example.org" || len(d.SANs.SPIFFE) != 1 || d.SANs.SPIFFE[0] != "spiffe://example.org/decoded" || d.SANs.IP[0] != "192.0.2.10" {
		t.Fatalf("sans %+v", d.SANs)
	}

	// Malformed stored PEM: 200 with a clear unavailable state, no crash.
	w = f.req(t, "GET", Prefix+"/certificates/"+detailsBadID+"/details", "admin", "")
	mustStatus(t, w, http.StatusOK)
	m := jsonBody(t, w)
	if m["available"] != false || m["error"] != certinfo.ErrUnavailable || m["reason"] == "" || m["details"] != nil {
		t.Fatalf("malformed result %+v", m)
	}

	// A caller who may not read the certificate gets the same answer as an
	// unknown one (existence never leaks).
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+detailsCertID+"/details", "bob", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+detailsCertID, "bob", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/66666666-6666-7666-8666-666666666666/details", "admin", ""), http.StatusNotFound)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+detailsCertID+"/details", "", ""), http.StatusUnauthorized)
}

func TestCertificateDetailsOfIssuedCertificate(t *testing.T) {
	f := newAPI(t)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)
	certID := f.issueAndWait(t, `{"spiffe_id":"spiffe://example.org/details"}`, "spiffe://example.org/details")
	w := f.req(t, "GET", Prefix+"/certificates/"+certID+"/details", "admin", "")
	mustStatus(t, w, http.StatusOK)
	var res certinfo.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Details.SANs.SPIFFE[0] != "spiffe://example.org/details" || len(res.Details.Chain) == 0 || res.Details.Validity.Status != certinfo.StatusValid {
		t.Fatalf("issued details %+v", res.Details)
	}
}
