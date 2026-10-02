package store

// AnyTrustDomain is the trust domain of an ACME issuer that is not bound to
// one trust domain. ACME issuance never compares an issuer's trust domain
// (there is no CA, no bundle and no SPIFFE ID check), so the value is pure
// metadata there; self-signed issuers sign SPIFFE IDs of exactly their trust
// domain and can never use it.
const AnyTrustDomain = "*"

// ValidTrustDomain reports whether host is a non-empty run (<=253 bytes) of
// lowercase letters, digits, dots and hyphens.
func ValidTrustDomain(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// ValidIssuerTrustDomain reports whether trustDomain is allowed for an issuer
// of issuerType: a DNS-style trust domain for every issuer, or AnyTrustDomain
// for ACME issuers only.
func ValidIssuerTrustDomain(issuerType, trustDomain string) bool {
	if trustDomain == AnyTrustDomain {
		return issuerType == "acme"
	}
	return ValidTrustDomain(trustDomain)
}
