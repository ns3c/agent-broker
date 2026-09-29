// Package token implements the access token: a compact JWS (EdDSA) whose
// claims follow RFC 8693 (act) for delegation.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	Issuer   = "grants"
	Audience = "tool-broker"
)

type Actor struct {
	Sub string `json:"sub"`
}

type Resource struct {
	Project string `json:"project"`
}

type Claims struct {
	Iss      string   `json:"iss"`
	Aud      string   `json:"aud"`
	Sub      string   `json:"sub"`
	Act      Actor    `json:"act"`
	Scope    string   `json:"scope"`
	Resource Resource `json:"resource"`
	Tenant   string   `json:"tenant"`
	Dlg      string   `json:"dlg"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	Jti      string   `json:"jti"`
}

func (c Claims) HasScope(s string) bool {
	for _, f := range strings.Fields(c.Scope) {
		if f == s {
			return true
		}
	}
	return false
}

func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Exp, 0) }

var header = b64([]byte(`{"alg":"EdDSA","typ":"at+jwt"}`))

func Sign(c Claims, key ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + b64(payload)
	return signingInput + "." + b64(ed25519.Sign(key, []byte(signingInput))), nil
}

var (
	ErrMalformed = errors.New("malformed token")
	ErrSignature = errors.New("bad signature")
)

// Verify checks the signature only; the broker checks claims itself so each
// check can be reported individually.
func Verify(tok string, pub ed25519.PublicKey) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != header {
		return c, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, ErrMalformed
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, ErrMalformed
	}
	return c, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
