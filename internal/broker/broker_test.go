package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/pki"
	"agentbroker/internal/token"
)

func TestAuthorize(t *testing.T) {
	ca, err := pki.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	b := &Broker{pub: pub}

	runA := pki.RunID(config.AgentType, "aaaa")
	runB := pki.RunID(config.AgentType, "bbbb")
	certFor := func(id string) *x509.Certificate {
		k, _ := pki.NewKey()
		c, err := ca.Issue(id, k.Public(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	claims := func(mut func(*token.Claims)) token.Claims {
		c := token.Claims{
			Iss: token.Issuer, Aud: token.Audience, Sub: "alice@demo",
			Act: token.Actor{Sub: runA}, Scope: "ticket:create",
			Resource: token.Resource{Project: "ENG"}, Tenant: "t1",
			Exp: time.Now().Add(10 * time.Second).Unix(), Jti: "j",
		}
		if mut != nil {
			mut(&c)
		}
		return c
	}
	sign := func(c token.Claims, k ed25519.PrivateKey) string {
		s, err := token.Sign(c, k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tests := []struct {
		name    string
		peer    string
		token   string
		project string
		want    string
	}{
		{"valid", runA, sign(claims(nil), priv), "ENG", ""},
		{"not an agent identity", pki.ServiceID("web"), sign(claims(nil), priv), "ENG", "identity_invalid"},
		{"no token", runA, "", "ENG", "token_invalid"},
		{"forged signature", runA, sign(claims(nil), otherPriv), "ENG", "token_invalid"},
		{"wrong audience", runA, sign(claims(func(c *token.Claims) { c.Aud = "jira" }), priv), "ENG", "token_invalid"},
		{"expired", runA, sign(claims(func(c *token.Claims) { c.Exp = time.Now().Add(-time.Second).Unix() }), priv), "ENG", "token_expired"},
		{"stolen: other run replays token", runB, sign(claims(nil), priv), "ENG", "binding_mismatch"},
		{"policy: unknown agent type", pki.RunID("deployer", "aaaa"),
			sign(claims(func(c *token.Claims) { c.Act.Sub = pki.RunID("deployer", "aaaa") }), priv), "ENG", "action_not_permitted"},
		{"scope not delegated", runA, sign(claims(func(c *token.Claims) { c.Scope = "ticket:read" }), priv), "ENG", "insufficient_scope"},
		{"resource outside grant", runA, sign(claims(nil), priv), "OPS", "resource_not_permitted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/tools/ticket.create", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certFor(tc.peer)}}
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			_, checks, code, _ := b.authorize(r, "ticket:create", tc.project)
			if code != tc.want {
				t.Fatalf("code = %q, want %q (checks %+v)", code, tc.want, checks)
			}
			if tc.want == "" && len(checks) != 7 {
				t.Fatalf("valid request ran %d checks, want 7", len(checks))
			}
		})
	}
}
