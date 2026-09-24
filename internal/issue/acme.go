package issue

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// ObtainACME issues a GENERIC certificate (not a SPIFFE SVID) for DNS domains
// via the issuer's ACME (Let's-Encrypt DNS-01) account: it opens the issuer's
// sealed ACME account key + DNS-provider credentials, runs the ACME order, and
// records the result as a kind="generic" issued certificate. csrPEM may be
// supplied by the caller (its key stays with the caller) or left empty to have
// lcm generate the keypair and return it once.
// PrecheckACME validates synchronously that the issuer exists, is an ACME issuer
// and the caller may use it — so an async caller can return a fast 400/403
// before backgrounding the slow order. It performs no network calls.
func (s *Service) PrecheckACME(ctx context.Context, subj authz.Subjects, issuerID string) error {
	issuer, err := s.st.GetIssuer(ctx, subj.TenantID, issuerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invalid("issuer_id", "issuer not found")
		}
		return err
	}
	if issuer.Type != "acme" {
		return invalid("issuer_id", "issuer is not an ACME issuer")
	}
	if err := s.az.Check(ctx, subj, authz.Issuer, issuer.ID, authz.Use); err != nil {
		return authz.ErrForbidden
	}
	return nil
}

func (s *Service) ObtainACME(ctx context.Context, subj authz.Subjects, issuerID string, domains []string, csrPEM string, deliverKey, autoRenew bool) (Bundle, error) {
	domains = normaliseDomains(domains)
	if len(domains) == 0 {
		return Bundle{}, invalid("domains", "at least one DNS domain is required")
	}
	issuer, err := s.st.GetIssuer(ctx, subj.TenantID, issuerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Bundle{}, invalid("issuer_id", "issuer not found")
		}
		return Bundle{}, err
	}
	if issuer.Type != "acme" {
		return Bundle{}, invalid("issuer_id", "issuer is not an ACME issuer")
	}
	if err := s.az.Check(ctx, subj, authz.Issuer, issuer.ID, authz.Use); err != nil {
		return Bundle{}, authz.ErrForbidden
	}

	client, err := s.acmeClientFor(issuer)
	if err != nil {
		return Bundle{}, err
	}
	if rerr := client.Register(ctx); rerr != nil {
		return Bundle{}, rerr
	}

	certID := store.NewID()
	var csrDER []byte
	var keyPEM string
	var keySealed []byte
	if csrPEM != "" {
		parsed, perr := csr.ParseCSR([]byte(csrPEM))
		if perr != nil {
			return Bundle{}, invalid("csr", "certificate request rejected")
		}
		csrDER = parsed.CSR.Raw
	} else {
		key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return Bundle{}, gerr
		}
		der, cerr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, key)
		if cerr != nil {
			return Bundle{}, cerr
		}
		csrDER = der
		keyDER, merr := x509.MarshalPKCS8PrivateKey(key)
		if merr != nil {
			return Bundle{}, merr
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if keySealed, err = s.env.Seal(pemKey, sealed.ADCertKey(certID)); err != nil {
			return Bundle{}, err
		}
		if deliverKey {
			keyPEM = string(pemKey)
		}
	}

	chainPEM, err := client.Obtain(ctx, csrDER, domains)
	if err != nil {
		return Bundle{}, err
	}
	leafPEM, restPEM, leaf, perr := splitChain(chainPEM)
	if perr != nil {
		return Bundle{}, perr
	}

	sansJSON, _ := json.Marshal(domains)
	row := store.IssuedCertificate{
		ID: certID, TenantID: subj.TenantID, IssuerID: issuer.ID, Kind: "generic",
		Serial: leaf.SerialNumber.String(), Subject: domains[0], SANs: sansJSON,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, FingerprintSHA256: csr.Fingerprint(leaf.Raw),
		Status: "active", CertPEM: leafPEM, ChainPEM: restPEM, KeySealed: keySealed, AutoRenew: autoRenew,
		Owner: subj.ActorID(), CreatedBy: userPtr(subj), UpdatedBy: userPtr(subj),
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if ierr := tx.InsertCertificate(ctx, row); ierr != nil {
			return ierr
		}
		if lerr := tx.InsertCertLog(ctx, []store.CertLogRow{{TS: s.now(), TenantID: subj.TenantID, CertificateID: certID, Event: "issued", IssuerID: issuer.ID, SpiffeID: domains[0]}}); lerr != nil {
			return lerr
		}
		return authz.New(tx).GrantOwner(ctx, subj.TenantID, authz.Certificate, certID, subj.UserID)
	})
	if err != nil {
		return Bundle{}, err
	}
	s.emit(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateIssued, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"domains": strings.Join(domains, ","), "issuer_id": issuer.ID, "serial": row.Serial, "kind": "generic"}})

	// The generated key is RETAINED (sealed in key_sealed), not cleared: generic
	// certificates keep their key in lcm so it can be re-downloaded, deployed and
	// auto-renewed later. It is also returned once here for convenience.
	stored, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return Bundle{}, err
	}
	perms, _, _, _ := s.az.Effective(ctx, subj, authz.Certificate, certID)
	return Bundle{Certificate: s.certView(stored, perms), CertPEM: leafPEM, ChainPEM: restPEM, KeyPEM: keyPEM}, nil
}

// acmeClientFor builds an ACME client from an issuer's sealed secrets.
func (s *Service) acmeClientFor(issuer store.Issuer) (*acme.Client, error) {
	settings := sealed.Settings{}
	if len(issuer.SettingsSealed) > 0 {
		clear, oerr := s.env.Open(issuer.SettingsSealed, sealed.ADIssuer(issuer.ID))
		if oerr != nil {
			return nil, oerr
		}
		dec, derr := sealed.Decode(clear)
		if derr != nil {
			return nil, derr
		}
		settings = dec
	}
	accountKey, err := parseAccountKey(asString(settings["acme_account_key"]))
	if err != nil {
		return nil, invalid("acme_account_key", "issuer has no usable ACME account key")
	}
	provider, err := s.dnsProvider(issuer, settings)
	if err != nil {
		return nil, invalid("dns_provider", "DNS provider could not be built")
	}
	// Optional External Account Binding (KID + base64url HMAC key) for CAs that
	// require it. The HMAC is stored base64url-encoded (standard for ACME EAB).
	eabKID := asString(settings["eab_kid"])
	var eabHMAC []byte
	if raw := asString(settings["eab_hmac_key"]); raw != "" {
		decoded, derr := decodeEABKey(raw)
		if derr != nil {
			return nil, invalid("eab_hmac_key", "EAB HMAC key is not valid base64")
		}
		eabHMAC = decoded
	}
	return acme.New(acme.Config{
		DirectoryURL: issuer.ACMEDirectoryURL, AccountEmail: issuer.ACMEEmail,
		AccountKey: accountKey, DNS: provider, AllowInsecure: isLoopbackURL(issuer.ACMEDirectoryURL),
		EABKeyID: eabKID, EABHMACKey: eabHMAC,
	})
}

// dnsProvider builds the issuer's DNS-01 provider; "freya-dns" acts for the
// issuer's tenant through the DNS module (no stored credentials).
func (s *Service) dnsProvider(issuer store.Issuer, settings sealed.Settings) (acme.DNSProvider, error) {
	deps := acme.ProviderDeps{TenantID: issuer.TenantID}
	if s.freyaDNS != nil {
		deps.FreyaDNS = s.freyaDNS
	}
	return acme.NewProviderWith(issuer.DNSProvider, credsMap(settings["dns_credential"]), deps)
}

// decodeEABKey accepts an EAB HMAC key in base64url (preferred, per ACME) or
// standard base64, with or without padding.
func decodeEABKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("issue: invalid base64 EAB key")
}

func normaliseDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func splitChain(chainPEM string) (leafPEM, restPEM string, leaf *x509.Certificate, err error) {
	rest := []byte(chainPEM)
	var blk *pem.Block
	blk, rest = pem.Decode(rest)
	if blk == nil {
		return "", "", nil, invalid("acme", "ACME returned no certificate")
	}
	leaf, err = x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})), strings.TrimSpace(string(rest)), leaf, nil
}

func parseAccountKey(pemStr string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, errors.New("issue: no account key PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if sg, ok := k.(crypto.Signer); ok {
			return sg, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("issue: unsupported account key")
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func credsMap(v any) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]string:
		return m
	case map[string]any:
		for k, val := range m {
			out[k] = asString(val)
		}
	}
	return out
}

func isLoopbackURL(u string) bool {
	return strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost") || strings.Contains(u, "[::1]")
}

// renewACME re-obtains a generic ACME certificate for the same domains as old,
// reusing old's stored private key when available (so pinned deployments keep a
// stable key) and superseding the old row. It preserves the original owner so
// an auto-renew by the system scheduler does not reassign ownership. It runs the
// same ACME order flow as ObtainACME.
func (s *Service) renewACME(ctx context.Context, subj authz.Subjects, old store.IssuedCertificate) (Bundle, error) {
	var domains []string
	if len(old.SANs) > 0 {
		_ = json.Unmarshal(old.SANs, &domains)
	}
	domains = normaliseDomains(domains)
	if len(domains) == 0 {
		if old.Subject == "" {
			return Bundle{}, invalid("domains", "certificate has no domains to renew")
		}
		domains = []string{old.Subject}
	}
	issuer, err := s.st.GetIssuer(ctx, subj.TenantID, old.IssuerID)
	if err != nil {
		return Bundle{}, err
	}
	client, err := s.acmeClientFor(issuer)
	if err != nil {
		return Bundle{}, err
	}
	if rerr := client.Register(ctx); rerr != nil {
		return Bundle{}, rerr
	}

	certID := store.NewID()
	// Reuse the stored key when we have it; otherwise mint a fresh one.
	var key crypto.Signer
	if len(old.KeySealed) > 0 {
		if clear, oerr := s.env.Open(old.KeySealed, sealed.ADCertKey(old.ID)); oerr == nil {
			if k, perr := parseAccountKey(string(clear)); perr == nil {
				key = k
			}
		}
	}
	if key == nil {
		gk, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return Bundle{}, gerr
		}
		key = gk
	}
	csrDER, cerr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, key)
	if cerr != nil {
		return Bundle{}, cerr
	}
	keyDER, merr := x509.MarshalPKCS8PrivateKey(key)
	if merr != nil {
		return Bundle{}, merr
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	keySealed, serr := s.env.Seal(pemKey, sealed.ADCertKey(certID))
	if serr != nil {
		return Bundle{}, serr
	}

	chainPEM, err := client.Obtain(ctx, csrDER, domains)
	if err != nil {
		return Bundle{}, err
	}
	leafPEM, restPEM, leaf, perr := splitChain(chainPEM)
	if perr != nil {
		return Bundle{}, perr
	}
	sansJSON, _ := json.Marshal(domains)
	row := store.IssuedCertificate{
		ID: certID, TenantID: subj.TenantID, IssuerID: issuer.ID, Kind: "generic",
		Serial: leaf.SerialNumber.String(), Subject: domains[0], SANs: sansJSON,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, FingerprintSHA256: csr.Fingerprint(leaf.Raw),
		Status: "active", CertPEM: leafPEM, ChainPEM: restPEM, KeySealed: keySealed, AutoRenew: old.AutoRenew,
		Owner: old.Owner, CreatedBy: userPtr(subj), UpdatedBy: userPtr(subj),
	}
	// Preserve the original owner's grant (no-op when the owner is a service
	// SPIFFE id rather than a user; the system scheduler keeps admin access).
	grantee := ""
	if old.Owner != "" && !strings.HasPrefix(old.Owner, "spiffe://") {
		grantee = old.Owner
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if ierr := tx.InsertCertificate(ctx, row); ierr != nil {
			return ierr
		}
		if lerr := tx.InsertCertLog(ctx, []store.CertLogRow{{TS: s.now(), TenantID: subj.TenantID, CertificateID: certID, Event: "renewed", IssuerID: issuer.ID, SpiffeID: domains[0]}}); lerr != nil {
			return lerr
		}
		return authz.New(tx).GrantOwner(ctx, subj.TenantID, authz.Certificate, certID, grantee)
	})
	if err != nil {
		return Bundle{}, err
	}
	if serr := s.st.SetCertificateStatus(ctx, subj.TenantID, old.ID, old.Status, &certID); serr != nil {
		return Bundle{}, serr
	}
	s.emit(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateRenewed, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"domains": strings.Join(domains, ","), "issuer_id": issuer.ID, "serial": row.Serial, "kind": "generic", "renewed_from": old.ID}})
	stored, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return Bundle{}, err
	}
	perms, _, _, _ := s.az.Effective(ctx, subj, authz.Certificate, certID)
	return Bundle{Certificate: s.certView(stored, perms), CertPEM: leafPEM, ChainPEM: restPEM}, nil
}
