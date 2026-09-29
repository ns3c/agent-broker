// Package grants is the grant service: it issues run-scoped workload
// identities, stores delegations, and exchanges a delegation for a
// short-lived access token. Revocation and user state are checked here, on
// demand, so the broker never has to call back.
package grants

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/events"
	"agentbroker/internal/httpx"
	"agentbroker/internal/pki"
	"agentbroker/internal/token"
)

const (
	TokenTTL = 10 * time.Second
	SVIDTTL  = 15 * time.Minute
)

type Delegation struct {
	ID        string     `json:"id"`
	Tenant    string     `json:"tenant"`
	Subject   string     `json:"subject"`
	Actor     string     `json:"actor"`
	Scope     []string   `json:"scope"`
	Project   string     `json:"project"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Service struct {
	ca      *pki.CA
	signing ed25519.PrivateKey
	ev      *events.Emitter

	mu          sync.Mutex
	delegations map[string]*Delegation
	users       map[string]bool     // subject -> active
	issuedRuns  map[string]struct{} // run IDs that already have a certificate
}

func Main() {
	dir := config.PKIDir()
	id, err := pki.LoadServiceIdentity(dir, "grants")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := pki.LoadCA(filepath.Join(dir, "grants"))
	if err != nil {
		log.Fatal(err)
	}
	sk, err := pki.LoadKey(filepath.Join(dir, "grants", "signing.key"))
	if err != nil {
		log.Fatal(err)
	}
	s := &Service{
		ca:          ca,
		signing:     sk.(ed25519.PrivateKey),
		ev:          events.NewEmitter("grants"),
		delegations: map[string]*Delegation{},
		users:       map[string]bool{config.Subject: true},
		issuedRuns:  map[string]struct{}{},
	}
	web, harness := pki.ServiceID("web"), pki.ServiceID("harness")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /svid", httpx.RequirePeer(s.svid, harness))
	mux.HandleFunc("POST /delegations", httpx.RequirePeer(s.createDelegation, web))
	mux.HandleFunc("POST /delegations/{id}/revoke", httpx.RequirePeer(s.revoke, web))
	mux.HandleFunc("POST /delegations/{id}/expire-in", httpx.RequirePeer(s.expireIn, web))
	mux.HandleFunc("POST /tenants/{tenant}/reset", httpx.RequirePeer(s.resetTenant, web))
	mux.HandleFunc("POST /token", s.token) // any run identity; bound actor checked inside
	httpx.Serve("grants", &http.Server{Addr: config.GrantsAddr, Handler: mux, TLSConfig: id.ServerTLS()}, true)
}

var runIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,48}$`)

// POST /svid — harness sends a public key, gets a certificate for one run.
// This stands in for SPIRE workload attestation: only the harness node may
// request agent identities, and only under /agent/code-reviewer/run/.
func (s *Service) svid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID     string `json:"run_id"`
		PublicKey string `json:"public_key"` // base64 PKIX DER
	}
	if err := httpx.ReadJSON(r, &req); err != nil || !runIDPattern.MatchString(req.RunID) {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "run_id")
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "public_key")
		return
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "public_key")
		return
	}
	// One certificate per run ID, ever. Otherwise a compromised harness could
	// mint a second certificate for a live run and ride its tokens.
	s.mu.Lock()
	_, dup := s.issuedRuns[req.RunID]
	if !dup {
		s.issuedRuns[req.RunID] = struct{}{}
	}
	s.mu.Unlock()
	if dup {
		httpx.Fail(w, http.StatusConflict, "run_id_already_issued", req.RunID)
		return
	}
	spiffeID := pki.RunID(config.AgentType, req.RunID)
	cert, err := s.ca.Issue(spiffeID, pub, SVIDTTL)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "issue_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"spiffe_id": spiffeID,
		"cert_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	})
}

// POST /delegations — the user (via web) delegates scope to one run.
func (s *Service) createDelegation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant     string   `json:"tenant"`
		Subject    string   `json:"subject"`
		Actor      string   `json:"actor"`
		Scope      []string `json:"scope"`
		Project    string   `json:"project"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil || req.Tenant == "" || req.TTLSeconds <= 0 {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	if _, _, ok := pki.ParseRunID(req.Actor); !ok {
		httpx.Fail(w, http.StatusBadRequest, "bad_actor", req.Actor)
		return
	}
	d := &Delegation{
		ID:        "dlg_" + pki.RandomHex(16),
		Tenant:    req.Tenant,
		Subject:   req.Subject,
		Actor:     req.Actor,
		Scope:     req.Scope,
		Project:   req.Project,
		ExpiresAt: time.Now().Add(time.Duration(req.TTLSeconds) * time.Second),
	}
	s.mu.Lock()
	s.delegations[d.ID] = d
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.delegations[r.PathValue("id")]
	if !ok {
		httpx.Fail(w, http.StatusNotFound, "not_found", "")
		return
	}
	now := time.Now()
	d.RevokedAt = &now
	httpx.WriteJSON(w, http.StatusOK, d)
}

// POST /delegations/{id}/expire-in — shortens a delegation's lifetime. The
// expiry scenario anchors expiry to the first ticket so it lands mid-run
// regardless of model latency.
func (s *Service) expireIn(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Seconds int `json:"seconds"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil || req.Seconds < 0 {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.delegations[r.PathValue("id")]
	if !ok {
		httpx.Fail(w, http.StatusNotFound, "not_found", "")
		return
	}
	if at := time.Now().Add(time.Duration(req.Seconds) * time.Second); at.Before(d.ExpiresAt) {
		d.ExpiresAt = at
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) resetTenant(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	s.mu.Lock()
	for id, d := range s.delegations {
		if d.Tenant == tenant {
			delete(s.delegations, id)
		}
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// POST /token — exchange a delegation for a short-lived access token. The
// delegation ID is not a secret: it only redeems over the mTLS identity it
// was bound to.
func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DelegationID string `json:"delegation_id"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	peer := pki.PeerID(r)
	_, peerRun, _ := pki.ParseRunID(peer)

	s.mu.Lock()
	d, found := s.delegations[req.DelegationID]
	var dc Delegation
	if found {
		dc = *d
	}
	active := found && s.users[dc.Subject]
	s.mu.Unlock()

	if !found {
		httpx.Fail(w, http.StatusForbidden, "delegation_not_found", "")
		return
	}
	_, boundRun, _ := pki.ParseRunID(dc.Actor)
	now := time.Now()

	checks := []events.Check{
		{Name: "caller is bound actor", OK: peer == dc.Actor, Detail: fmt.Sprintf("peer run/%s, bound run/%s", peerRun, boundRun)},
		{Name: "not revoked", OK: dc.RevokedAt == nil},
		{Name: "not expired", OK: now.Before(dc.ExpiresAt), Detail: "expires " + dc.ExpiresAt.Format("15:04:05")},
		{Name: "user active", OK: active, Detail: dc.Subject},
	}
	codes := []string{"actor_mismatch", "delegation_revoked", "delegation_expired", "user_inactive"}
	for i, c := range checks {
		if !c.OK {
			s.ev.Emit(events.Event{
				Tenant: dc.Tenant, RunID: boundRun, Type: "token.exchange", Result: "deny",
				Summary: "token exchange denied: " + codes[i], Checks: checks[:i+1],
			})
			httpx.Fail(w, http.StatusForbidden, codes[i], "")
			return
		}
	}

	claims := token.Claims{
		Iss:      token.Issuer,
		Aud:      token.Audience,
		Sub:      dc.Subject,
		Act:      token.Actor{Sub: dc.Actor},
		Scope:    joinScope(dc.Scope),
		Resource: token.Resource{Project: dc.Project},
		Tenant:   dc.Tenant,
		Dlg:      dc.ID,
		Iat:      now.Unix(),
		Exp:      now.Add(TokenTTL).Unix(),
		Jti:      pki.RandomHex(4),
	}
	tok, err := token.Sign(claims, s.signing)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "sign_failed", "")
		return
	}
	s.ev.Emit(events.Event{
		Tenant: dc.Tenant, RunID: boundRun, Type: "token.exchange", Result: "ok",
		Summary: fmt.Sprintf("access token issued (jti %s, exp %s)", claims.Jti, claims.ExpiresAt().Format("15:04:05")),
		Checks:  checks,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_at": claims.Exp, "jti": claims.Jti})
}

func joinScope(s []string) string {
	s = slices.Clone(s)
	slices.Sort(s)
	return strings.Join(s, " ")
}
