// Package broker is the tool broker. It holds the only Jira credential,
// verifies the caller's workload identity and access token entirely offline,
// authorizes the action, and makes the external call itself.
package broker

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/events"
	"agentbroker/internal/httpx"
	"agentbroker/internal/pki"
	"agentbroker/internal/token"
)

// All services share one clock here; skew tolerance would only widen the
// revocation window.
const clockSkew = 0

// policy is the static authorization table: which actions each agent type
// may ever perform, regardless of what a grant says. A policy engine
// (Cedar/OPA) would replace this map.
var policy = map[string][]string{
	config.AgentType: {"ticket:create"},
}

// actions maps broker routes to the action they require.
var actions = map[string]string{
	"ticket.create": "ticket:create",
}

type Broker struct {
	pub     ed25519.PublicKey
	jiraKey string
	jira    *http.Client
	ev      *events.Emitter
}

func Main() {
	dir := config.PKIDir()
	id, err := pki.LoadServiceIdentity(dir, "broker")
	if err != nil {
		log.Fatal(err)
	}
	pub, err := pki.LoadEd25519Public(filepath.Join(dir, "broker", "signing.pub"))
	if err != nil {
		log.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, "broker", "jira.key"))
	if err != nil {
		log.Fatal(err)
	}
	b := &Broker{
		pub:     pub,
		jiraKey: strings.TrimSpace(string(key)),
		jira:    &http.Client{Timeout: 5 * time.Second},
		ev:      events.NewEmitter("broker"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tools/{tool}", b.handle)
	httpx.Serve("broker", &http.Server{Addr: config.BrokerAddr, Handler: mux, TLSConfig: id.ServerTLS()}, true)
}

type ticketRequest struct {
	Project string `json:"project"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	idemKey string // from the Idempotency-Key header
}

var idemKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (b *Broker) handle(w http.ResponseWriter, r *http.Request) {
	action, ok := actions[r.PathValue("tool")]
	if !ok {
		httpx.Fail(w, http.StatusNotFound, "unknown_tool", "")
		return
	}
	var req ticketRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	req.idemKey = r.Header.Get("Idempotency-Key")
	if req.idemKey != "" && !idemKeyPattern.MatchString(req.idemKey) {
		httpx.Fail(w, http.StatusBadRequest, "bad_idempotency_key", "")
		return
	}

	claims, checks, code, status := b.authorize(r, action, req.Project)
	_, runID, _ := pki.ParseRunID(claims.Act.Sub)
	if code != "" {
		// Only a signature-verified token tells us which tenant to report to.
		b.ev.Emit(events.Event{
			Tenant: claims.Tenant, RunID: runID, Type: "broker.decision", Result: "deny",
			Summary: fmt.Sprintf("%s denied: %s", action, code), Checks: checks,
		})
		httpx.Fail(w, status, code, "")
		return
	}

	issue, err := b.createIssue(claims, req)
	if err != nil {
		b.ev.Emit(events.Event{
			Tenant: claims.Tenant, RunID: runID, Type: "broker.decision", Result: "error",
			Summary: action + " allowed, but Jira call failed", Checks: checks,
		})
		httpx.Fail(w, http.StatusBadGateway, "upstream_error", "")
		return
	}
	if issue.Replayed {
		b.ev.Emit(events.Event{
			Tenant: claims.Tenant, RunID: runID, Type: "broker.decision", Result: "ok",
			Summary: fmt.Sprintf("%s allowed → retry matched %s by idempotency key; no duplicate created", action, issue.Key), Checks: checks,
		})
	} else {
		b.ev.Emit(events.Event{
			Tenant: claims.Tenant, RunID: runID, Type: "broker.decision", Result: "ok",
			Summary: fmt.Sprintf("%s allowed → %s created with broker's Jira key", action, issue.Key), Checks: checks,
		})
		b.ev.Emit(events.Event{
			Tenant: claims.Tenant, RunID: runID, Type: "ticket.created", Result: "info",
			Summary: issue.Key + ": " + issue.Title,
		})
	}
	// Minimal result: the harness never sees Jira internals.
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"key": issue.Key, "title": issue.Title})
}

// authorize runs every check offline, in order, and stops at the first
// failure. It returns the claims (zero value if the token didn't verify), the
// checks performed, and a deny code + HTTP status if denied.
func (b *Broker) authorize(r *http.Request, action, project string) (token.Claims, []events.Check, string, int) {
	var checks []events.Check
	fail := func(name, detail, code string, status int) (token.Claims, []events.Check, string, int) {
		checks = append(checks, events.Check{Name: name, OK: false, Detail: detail})
		return token.Claims{}, checks, code, status
	}

	// 1. Identity: the TLS handshake already required a cert chained to the
	//    demo CA; here we require that it is an agent run identity.
	peer := pki.PeerID(r)
	peerType, peerRun, isRun := pki.ParseRunID(peer)
	if !isRun {
		return fail("workload identity", "peer "+peer+" is not an agent run", "identity_invalid", http.StatusUnauthorized)
	}
	checks = append(checks, events.Check{Name: "workload identity (mTLS)", OK: true, Detail: "run/" + peerRun})

	// 2. Signature, issuer, audience.
	raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		return fail("token signature", "no bearer token", "token_invalid", http.StatusUnauthorized)
	}
	claims, err := token.Verify(raw, b.pub)
	if err != nil {
		return fail("token signature", err.Error(), "token_invalid", http.StatusUnauthorized)
	}
	if claims.Iss != token.Issuer || claims.Aud != token.Audience {
		checks = append(checks, events.Check{Name: "token signature + aud", OK: false, Detail: "iss/aud mismatch"})
		return claims, checks, "token_invalid", http.StatusUnauthorized
	}
	checks = append(checks, events.Check{Name: "token signature + aud", OK: true, Detail: "jti " + claims.Jti})

	deny := func(name, detail, code string, status int) (token.Claims, []events.Check, string, int) {
		checks = append(checks, events.Check{Name: name, OK: false, Detail: detail})
		return claims, checks, code, status
	}

	// 3. Expiry.
	now := time.Now()
	if now.After(claims.ExpiresAt().Add(clockSkew)) {
		return deny("not expired", "expired "+claims.ExpiresAt().Format("15:04:05"), "token_expired", http.StatusUnauthorized)
	}
	checks = append(checks, events.Check{Name: "not expired", OK: true, Detail: fmt.Sprintf("%.0fs left", time.Until(claims.ExpiresAt()).Seconds())})

	// 4. Binding: the token only works over the mTLS identity it was issued to.
	_, boundRun, _ := pki.ParseRunID(claims.Act.Sub)
	if peer != claims.Act.Sub {
		return deny("token bound to caller", fmt.Sprintf("peer run/%s ≠ act run/%s", peerRun, boundRun), "binding_mismatch", http.StatusForbidden)
	}
	checks = append(checks, events.Check{Name: "token bound to caller", OK: true, Detail: "act = peer"})

	// 5. Policy: may this agent type ever do this?
	if !slices.Contains(policy[peerType], action) {
		return deny("policy", peerType+" may not "+action, "action_not_permitted", http.StatusForbidden)
	}
	checks = append(checks, events.Check{Name: "policy", OK: true, Detail: peerType + " may " + action})

	// 6. Scope: did the user delegate this action?
	if !claims.HasScope(action) {
		return deny("scope", "scope "+claims.Scope, "insufficient_scope", http.StatusForbidden)
	}
	checks = append(checks, events.Check{Name: "scope", OK: true, Detail: action})

	// 7. Resource: is the target within the grant?
	if project != claims.Resource.Project {
		return deny("resource", fmt.Sprintf("project %q not in grant", project), "resource_not_permitted", http.StatusForbidden)
	}
	checks = append(checks, events.Check{Name: "resource", OK: true, Detail: "project " + project})

	return claims, checks, "", 0
}

type issue struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	Replayed bool   `json:"replayed"`
}

func (b *Broker) createIssue(c token.Claims, req ticketRequest) (issue, error) {
	_, runID, _ := pki.ParseRunID(c.Act.Sub)
	var out issue
	headers := map[string]string{"Authorization": "Bearer " + b.jiraKey, "X-Tenant": c.Tenant}
	if req.idemKey != "" {
		// Namespaced by the authenticated run, so one run's key can never
		// match another run's ticket.
		headers["Idempotency-Key"] = runID + ":" + req.idemKey
	}
	err := httpx.PostJSON(b.jira, config.JiraURL+"/rest/api/issue", headers,
		map[string]string{
			"project":      req.Project,
			"title":        req.Title,
			"body":         req.Body,
			"reporter":     "tool-broker",
			"on_behalf_of": fmt.Sprintf("%s via %s run %s", c.Sub, config.AgentType, runID),
			"run_id":       runID,
		}, &out)
	if err == nil && out.Key == "" {
		err = errors.New("empty issue key")
	}
	return out, err
}
