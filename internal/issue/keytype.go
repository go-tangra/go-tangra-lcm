package issue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Key types an issuer may set in settings.key_type for the keys lcm generates
// for its certificates. An issuer without one gets DefaultKeyType.
const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeRSA2048   = "rsa-2048"
	KeyTypeRSA4096   = "rsa-4096"
	DefaultKeyType   = KeyTypeECDSAP256
)

func validKeyType(kt string) bool {
	switch kt {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
		return true
	}
	return false
}

// settingsKeyType reads key_type from issuer settings; "" when unset.
func settingsKeyType(s sealed.Settings) string {
	kt, _ := s["key_type"].(string)
	return kt
}

// issuerKeyType is the key type the issuer's generated certificate keys use.
// key_type is not a secret, so it is read from the public settings.
func issuerKeyType(row store.Issuer) string {
	if kt := settingsKeyType(redacted(row)); validKeyType(kt) {
		return kt
	}
	return DefaultKeyType
}

// generateKey mints a private key of the given type (DefaultKeyType when
// the type is not recognised).
func generateKey(kt string) (crypto.Signer, error) {
	switch kt {
	case KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}
