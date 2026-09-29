// Package harness runs the reviewer agent and is the only component that
// holds agent credentials: the run's private key, its delegation ID and its
// access token. The model emits intent (create_ticket); the harness decides
// how, and with what credential, that intent is carried out.
package harness

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/events"
	"agentbroker/internal/httpx"
	"agentbroker/internal/pki"
)

const (
	refreshBefore = 3 * time.Second
	brokerPacing  = 5 * time.Second
	runTimeout    = 3 * time.Minute
)

// Messages the model receives. Fixed strings only: no tokens, IDs, deny
// codes or reasons ever reach the model's context.
const (
	msgTerminal    = "Grant no longer available. Do not retry. Summarize your findings instead."
	msgUnavailable = "Ticket service temporarily unavailable. Continue your review."
	msgLimit       = "Ticket limit reached. Summarize any remaining findings instead."
)

type Harness struct {
	node   *pki.Identity // svc/harness: used only to request run identities
	grants *http.Client
	ev     *events.Emitter

	mu   sync.Mutex
	runs map[string]*Run
}

func Main() {
	node, err := pki.LoadServiceIdentity(config.PKIDir(), "harness")
	if err != nil {
		log.Fatal(err)
	}
	h := &Harness{
		node:   node,
		grants: node.Client(pki.ServiceID("grants")),
		ev:     events.NewEmitter("harness"),
		runs:   map[string]*Run{},
	}
	web := pki.ServiceID("web")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /runs", httpx.RequirePeer(h.createRun, web))
	mux.HandleFunc("POST /runs/{id}/start", httpx.RequirePeer(h.startRun, web))
	mux.HandleFunc("POST /runs/{id}/cancel", httpx.RequirePeer(h.cancelRun, web))
	httpx.Serve("harness", &http.Server{Addr: config.HarnessAddr, Handler: mux, TLSConfig: node.ServerTLS()}, true)
}

// mintIdentity generates a keypair locally and asks grants to certify only
// the public half. The private key never leaves this process.
func (h *Harness) mintIdentity(runID string) (*pki.Identity, error) {
	key, err := pki.NewKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	var resp struct {
		SpiffeID string `json:"spiffe_id"`
		CertPEM  string `json:"cert_pem"`
	}
	err = httpx.PostJSON(h.grants, config.GrantsURL+"/svid", nil,
		map[string]string{"run_id": runID, "public_key": base64.StdEncoding.EncodeToString(der)}, &resp)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode([]byte(resp.CertPEM))
	if blk == nil {
		return nil, errors.New("svid: bad PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return h.node.Derive(cert, key), nil
}

func (h *Harness) createRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant   string `json:"tenant"`
		RunID    string `json:"run_id"`
		Scenario string `json:"scenario"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil || req.Tenant == "" {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	id, err := h.mintIdentity(req.RunID)
	if err != nil {
		httpx.Fail(w, http.StatusBadGateway, "svid_failed", err.Error())
		return
	}
	run := &Run{h: h, ID: req.RunID, Tenant: req.Tenant, Scenario: req.Scenario, id: id}
	run.grants = id.Client(pki.ServiceID("grants"))
	run.broker = id.Client(pki.ServiceID("broker"))
	h.mu.Lock()
	h.runs[run.ID] = run
	h.mu.Unlock()
	run.emit("run.identity", "info", "workload identity issued: "+id.ID+" (private key held by harness)", nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"spiffe_id": id.ID})
}

func (h *Harness) startRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DelegationID string `json:"delegation_id"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil || req.DelegationID == "" {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	h.mu.Lock()
	run, ok := h.runs[r.PathValue("id")]
	h.mu.Unlock()
	if !ok {
		httpx.Fail(w, http.StatusNotFound, "not_found", "")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	run.mu.Lock()
	run.delegationID = req.DelegationID
	run.cancel = cancel
	run.mu.Unlock()
	go func() {
		defer cancel()
		run.agent(ctx)
		h.mu.Lock()
		delete(h.runs, run.ID)
		h.mu.Unlock()
	}()
	w.WriteHeader(http.StatusAccepted)
}

func (h *Harness) cancelRun(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	run, ok := h.runs[r.PathValue("id")]
	h.mu.Unlock()
	if ok {
		run.mu.Lock()
		if run.cancel != nil {
			run.cancel()
		}
		run.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// Run is one agent execution with its own workload identity.
type Run struct {
	h        *Harness
	ID       string
	Tenant   string
	Scenario string

	id     *pki.Identity
	grants *http.Client // mTLS as this run
	broker *http.Client // mTLS as this run

	mu           sync.Mutex
	cancel       context.CancelFunc
	delegationID string
	token        string
	tokenExp     time.Time
	lastBroker   time.Time
	disabled     bool // terminal: brokered tools are off for the rest of the run
	tickets      int
}

func (r *Run) emit(typ, result, summary string, data []byte) {
	r.h.ev.Emit(events.Event{Tenant: r.Tenant, RunID: r.ID, Type: typ, Result: result, Summary: summary, Data: data})
}

// failure classes
type class int

const (
	classTerminal class = iota
	classRetryable
	classExpired
)

func classify(err error) (class, string) {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.Body.Error == "token_expired":
			return classExpired, se.Body.Error
		case se.Status >= 500:
			return classRetryable, se.Body.Error
		default:
			return classTerminal, se.Body.Error
		}
	}
	return classRetryable, "unreachable"
}

// accessToken returns a cached token, refreshing it from grants when it is
// missing, forced, or within refreshBefore of expiry.
func (r *Run) accessToken(force bool) (string, error) {
	r.mu.Lock()
	tok, exp, dlg := r.token, r.tokenExp, r.delegationID
	r.mu.Unlock()
	left := time.Until(exp)
	if tok != "" && !force && left > refreshBefore {
		return tok, nil
	}
	if tok != "" {
		r.emit("harness.refresh", "info", fmt.Sprintf("refreshing access token (%.1fs left)", max(left.Seconds(), 0)), nil)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := httpx.PostJSON(r.grants, config.GrantsURL+"/token", nil, map[string]string{"delegation_id": dlg}, &resp); err != nil {
		return "", err
	}
	r.mu.Lock()
	r.token, r.tokenExp = resp.AccessToken, time.Unix(resp.ExpiresAt, 0)
	r.mu.Unlock()
	return resp.AccessToken, nil
}

// createTicket carries out the model's intent. Everything credential-related
// happens here; the return value is the only thing the model sees.
func (r *Run) createTicket(ctx context.Context, title, body string) string {
	r.mu.Lock()
	disabled, tickets := r.disabled, r.tickets
	wait := time.Until(r.lastBroker.Add(brokerPacing))
	r.mu.Unlock()
	if disabled {
		r.emit("harness.skip", "deny", "create_ticket not attempted: grant already unavailable", nil)
		return msgTerminal
	}
	if tickets >= maxTickets {
		return msgLimit
	}
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return msgUnavailable
		}
	}
	defer func() {
		r.mu.Lock()
		r.lastBroker = time.Now()
		r.mu.Unlock()
	}()

	var key, keyTitle string
	var lastErr error
	refreshed := false
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		tok, err := r.accessToken(false)
		if err == nil {
			var out struct {
				Key   string `json:"key"`
				Title string `json:"title"`
			}
			err = httpx.PostJSON(r.broker, config.BrokerURL+"/v1/tools/ticket.create",
				map[string]string{"Authorization": "Bearer " + tok},
				map[string]string{"project": config.Project, "title": title, "body": body}, &out)
			key, keyTitle = out.Key, out.Title
		}
		if err == nil {
			break
		}
		lastErr = err
		cls, code := classify(err)
		switch cls {
		case classExpired:
			if !refreshed {
				refreshed = true
				r.mu.Lock()
				r.token = ""
				r.mu.Unlock()
				attempt-- // a refresh is not a retry
				continue
			}
			fallthrough
		case classTerminal:
			r.mu.Lock()
			r.disabled = true
			r.mu.Unlock()
			r.emit("harness.classify", "deny",
				fmt.Sprintf("%s → terminal: brokered tools disabled; model told “Grant no longer available”", code), nil)
			return msgTerminal
		case classRetryable:
			r.emit("harness.classify", "error", fmt.Sprintf("%s → retryable (attempt %d)", code, attempt+1), nil)
		}
	}
	if key == "" {
		r.emit("harness.classify", "error", fmt.Sprintf("retries exhausted (%v); model told service unavailable", lastErr), nil)
		return msgUnavailable
	}

	r.mu.Lock()
	r.tickets++
	first := r.tickets == 1
	r.mu.Unlock()
	if first && r.Scenario == "stolen" {
		r.simulateTheft()
	}
	return fmt.Sprintf("Created %s: %s", key, keyTitle)
}

// simulateTheft plays a second workload that has somehow obtained this run's
// access token and delegation ID. It holds a perfectly valid identity of its
// own — just not the one the grant was bound to. The token never leaves this
// process; the "thief" is a separate identity inside the harness.
func (r *Run) simulateTheft() {
	thiefRun := r.ID + "-x"
	thief, err := r.h.mintIdentity(thiefRun)
	if err != nil {
		r.emit("scenario", "error", "could not mint second workload: "+err.Error(), nil)
		return
	}
	r.mu.Lock()
	tok, dlg := r.token, r.delegationID
	r.mu.Unlock()
	r.emit("scenario", "info", fmt.Sprintf("simulated leak: second workload run/%s replays run/%s's access token and delegation ID", thiefRun, r.ID), nil)

	broker := thief.Client(pki.ServiceID("broker"))
	err = httpx.PostJSON(broker, config.BrokerURL+"/v1/tools/ticket.create",
		map[string]string{"Authorization": "Bearer " + tok},
		map[string]string{"project": config.Project, "title": "stolen-token replay", "body": "should never be created"}, nil)
	r.emit("scenario", resultOf(err), "stolen token → broker: "+outcome(err), nil)

	grants := thief.Client(pki.ServiceID("grants"))
	err = httpx.PostJSON(grants, config.GrantsURL+"/token", nil, map[string]string{"delegation_id": dlg}, nil)
	r.emit("scenario", resultOf(err), "stolen delegation ID → grants /token: "+outcome(err), nil)
}

func outcome(err error) string {
	var se *httpx.StatusError
	if errors.As(err, &se) {
		return "denied (" + se.Body.Error + ")"
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return "ACCEPTED"
}

func resultOf(err error) string {
	if err != nil {
		return "deny"
	}
	return "error"
}
