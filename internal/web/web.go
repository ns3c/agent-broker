// Package web is the reviewer-facing dashboard. It plays "the user": it
// creates and revokes delegations and shows what happened. It never holds an
// access token or any private key other than its own service identity.
package web

import (
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/events"
	"agentbroker/internal/httpx"
	"agentbroker/internal/pki"
)

//go:embed static
var static embed.FS

const (
	delegationTTL    = 10 * time.Minute
	expireAfterFirst = 6 * time.Second
	// The harness gives up on a run after 3 minutes; if no final status has
	// arrived by this point, it never will.
	runStaleAfter = 4 * time.Minute
	runsPerHour   = 5
	sessionIdle   = 24 * time.Hour
	maxSessions   = 1000
)

var scenarios = map[string]bool{"normal": true, "expire": true, "revoke": true, "stolen": true}

type RunState struct {
	ID            string    `json:"id"`
	Scenario      string    `json:"scenario"`
	Status        string    `json:"status"`
	SpiffeID      string    `json:"spiffe_id"`
	DelegationID  string    `json:"delegation_id"`
	DelegationExp time.Time `json:"delegation_expires_at"`
	Started       time.Time `json:"started"`
	Final         string    `json:"final,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
}

// ticket is a Jira issue as the dashboard sees it.
type ticket struct {
	Key        string    `json:"key"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Reporter   string    `json:"reporter"`
	OnBehalfOf string    `json:"on_behalf_of"`
	RunID      string    `json:"run_id"`
	Created    time.Time `json:"created"`
}

type Session struct {
	Tenant    string
	LastSeen  time.Time
	Run       *RunState
	Events    []events.Event
	Context   json.RawMessage
	RunStarts []time.Time
}

type Server struct {
	harness *http.Client
	grants  *http.Client
	jira    *http.Client

	dailyCap int

	mu       sync.Mutex
	sessions map[string]*Session // sid -> session
	tenants  map[string]*Session // tenant -> session
	day      string
	dayRuns  int
}

func Main() {
	password := os.Getenv("DEMO_PASSWORD")
	if password == "" {
		log.Fatal("DEMO_PASSWORD must be set (e.g. in .env)")
	}
	id, err := pki.LoadServiceIdentity(config.PKIDir(), "web")
	if err != nil {
		log.Fatal(err)
	}
	dailyCap, _ := strconv.Atoi(config.Env("RUNS_PER_DAY", "300"))
	s := &Server{
		harness:  id.Client(pki.ServiceID("harness")),
		grants:   id.Client(pki.ServiceID("grants")),
		jira:     &http.Client{Timeout: 3 * time.Second},
		dailyCap: dailyCap,
		sessions: map[string]*Session{},
		tenants:  map[string]*Session{},
	}
	go s.evictLoop()

	ingest := http.NewServeMux()
	ingest.HandleFunc("POST /events", s.ingest)
	go httpx.Serve("web-ingest", &http.Server{Addr: config.EventsAddr, Handler: ingest}, false)

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(mustSub(static, "static")))
	mux.HandleFunc("GET /api/state", s.withSession(s.state))
	mux.HandleFunc("POST /api/runs", s.withSession(s.startRun))
	mux.HandleFunc("POST /api/reset", s.withSession(s.reset))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	g := newGate(password)
	srv := &http.Server{Addr: ":" + config.Env("PORT", "8080"), Handler: g.wrap(mux)}
	// Public HTTPS when a certificate is mounted; plain HTTP otherwise (local dev).
	if certFile, keyFile := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("TLS: %v", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	httpx.Serve("web", srv, srv.TLSConfig != nil)
}

// ---- sessions ----

type sessionHandler func(w http.ResponseWriter, r *http.Request, s *Session)

func (s *Server) withSession(h sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid := ""
		if c, err := r.Cookie("sid"); err == nil {
			sid = c.Value
		}
		s.mu.Lock()
		sess, ok := s.sessions[sid]
		if !ok {
			sid = pki.RandomHex(16)
			sum := sha256.Sum256([]byte(sid))
			sess = &Session{Tenant: "t_" + hex.EncodeToString(sum[:6])}
			s.evictOldestLocked()
			s.sessions[sid] = sess
			s.tenants[sess.Tenant] = sess
			http.SetCookie(w, &http.Cookie{
				Name: "sid", Value: sid, Path: "/", MaxAge: 30 * 24 * 3600,
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
				Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			})
		}
		sess.LastSeen = time.Now()
		s.mu.Unlock()
		h(w, r, sess)
	}
}

func (s *Server) evictOldestLocked() {
	if len(s.sessions) < maxSessions {
		return
	}
	var oldest string
	for sid, sess := range s.sessions {
		if oldest == "" || sess.LastSeen.Before(s.sessions[oldest].LastSeen) {
			oldest = sid
		}
	}
	delete(s.tenants, s.sessions[oldest].Tenant)
	delete(s.sessions, oldest)
}

func (s *Server) evictLoop() {
	for range time.Tick(10 * time.Minute) {
		s.mu.Lock()
		for sid, sess := range s.sessions {
			if time.Since(sess.LastSeen) > sessionIdle {
				delete(s.tenants, sess.Tenant)
				delete(s.sessions, sid)
			}
		}
		s.mu.Unlock()
	}
}

// ---- event ingest (internal, localhost only) ----

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	var ev events.Event
	if err := httpx.ReadJSON(r, &ev); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)

	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.tenants[ev.Tenant]
	if !ok || sess.Run == nil || sess.Run.ID != ev.RunID {
		return
	}
	switch ev.Type {
	case "model.context":
		sess.Context = ev.Data
		return
	case "run.status":
		var d struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(ev.Data, &d) == nil && d.Status != "" {
			sess.Run.Status = d.Status
		}
	case "model.final":
		sess.Run.Final = ev.Summary
		ev.Summary = "model final answer received"
	case "broker.decision":
		// The broker verifies offline, so a revoked grant's current token keeps
		// working until it expires. Make that window visible.
		if ev.Result == "ok" && !sess.Run.RevokedAt.IsZero() {
			ev.Summary += fmt.Sprintf(" · inside revocation window (revoked %.0fs ago; token not yet expired)",
				time.Since(sess.Run.RevokedAt).Seconds())
		}
	}
	ev.Data = nil
	sess.Events = append(sess.Events, ev)
}

// watchFirstTicket polls Jira, the source of truth, until this run has filed
// a ticket, then fires the revoke/expire scenario so it lands mid-run
// regardless of model latency. It does not depend on best-effort events.
func (s *Server) watchFirstTicket(sess *Session, run RunState) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		s.mu.Lock()
		live := sess.Run != nil && sess.Run.ID == run.ID && (sess.Run.Status == "starting" || sess.Run.Status == "running")
		s.mu.Unlock()
		if !live || time.Since(run.Started) > runStaleAfter {
			return
		}
		for _, t := range s.tickets(sess.Tenant) {
			if t.RunID == run.ID {
				s.firstTicketTrigger(sess, run)
				return
			}
		}
	}
}

func (s *Server) firstTicketTrigger(sess *Session, run RunState) {
	switch run.Scenario {
	case "revoke":
		err := httpx.PostJSON(s.grants, config.GrantsURL+"/delegations/"+run.DelegationID+"/revoke", nil, struct{}{}, nil)
		s.mu.Lock()
		if sess.Run != nil && sess.Run.ID == run.ID && err == nil {
			sess.Run.RevokedAt = time.Now()
		}
		s.mu.Unlock()
		s.localEvent(sess, run.ID, "user.revoke", "deny",
			"user revoked "+run.DelegationID+" — the issued token stays valid until it expires; revocation is enforced at the next exchange"+errSuffix(err))
	case "expire":
		var d struct {
			ExpiresAt time.Time `json:"expires_at"`
		}
		err := httpx.PostJSON(s.grants, config.GrantsURL+"/delegations/"+run.DelegationID+"/expire-in", nil,
			map[string]int{"seconds": int(expireAfterFirst.Seconds())}, &d)
		s.mu.Lock()
		if sess.Run != nil && sess.Run.ID == run.ID && err == nil {
			sess.Run.DelegationExp = d.ExpiresAt
		}
		s.mu.Unlock()
		s.localEvent(sess, run.ID, "user.expiry", "info",
			fmt.Sprintf("delegation %s now expires at %s (anchored to first ticket)", run.DelegationID, d.ExpiresAt.Format("15:04:05"))+errSuffix(err))
	}
}

func (s *Server) localEvent(sess *Session, runID, typ, result, summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.Run == nil || sess.Run.ID != runID {
		return
	}
	sess.Events = append(sess.Events, events.Event{
		Tenant: sess.Tenant, RunID: runID, TS: time.Now(), Component: "user", Type: typ, Result: result, Summary: summary,
	})
}

func errSuffix(err error) string {
	if err != nil {
		return " (error: " + err.Error() + ")"
	}
	return ""
}

// ---- API ----

func (s *Server) tickets(tenant string) []ticket {
	var out []ticket
	if resp, err := s.jira.Get(config.JiraURL + "/internal/issues?tenant=" + tenant); err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
	}
	return out
}

// markStaleLocked fails a run whose final status never arrived (harness
// restarted, event lost) so the session can't sit in "running" forever.
func markStaleLocked(sess *Session) {
	r := sess.Run
	if r == nil || (r.Status != "starting" && r.Status != "running") || time.Since(r.Started) < runStaleAfter {
		return
	}
	r.Status = "failed"
	sess.Events = append(sess.Events, events.Event{
		Tenant: sess.Tenant, RunID: r.ID, TS: time.Now(), Component: "web", Type: "run.status", Result: "error",
		Summary: fmt.Sprintf("no final status within %s; run marked failed", runStaleAfter),
	})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request, sess *Session) {
	tickets := s.tickets(sess.Tenant)
	s.mu.Lock()
	markStaleLocked(sess)
	evs := append([]events.Event{}, sess.Events...)
	var run *RunState
	if sess.Run != nil {
		cp := *sess.Run
		run = &cp
	}
	ctx := sess.Context
	runsLeft := runsPerHour - recent(sess.RunStarts)
	s.mu.Unlock()
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].TS.Before(evs[j].TS) })
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"run": run, "events": evs, "model_context": ctx, "tickets": tickets, "runs_left": runsLeft,
		"subject": config.Subject,
	})
}

func recent(ts []time.Time) int {
	n := 0
	for _, t := range ts {
		if time.Since(t) < time.Hour {
			n++
		}
	}
	return n
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request, sess *Session) {
	var req struct {
		Scenario string `json:"scenario"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil || !scenarios[req.Scenario] {
		httpx.Fail(w, http.StatusBadRequest, "bad_scenario", "")
		return
	}
	runID := pki.RandomHex(4)

	s.mu.Lock()
	markStaleLocked(sess)
	if sess.Run != nil && (sess.Run.Status == "starting" || sess.Run.Status == "running") {
		s.mu.Unlock()
		httpx.Fail(w, http.StatusConflict, "run_in_progress", "wait for the current run to finish or reset")
		return
	}
	if recent(sess.RunStarts) >= runsPerHour {
		s.mu.Unlock()
		httpx.Fail(w, http.StatusTooManyRequests, "session_rate_limited", fmt.Sprintf("%d runs per hour per session", runsPerHour))
		return
	}
	if today := time.Now().UTC().Format("2006-01-02"); today != s.day {
		s.day, s.dayRuns = today, 0
	}
	if s.dayRuns >= s.dailyCap {
		s.mu.Unlock()
		httpx.Fail(w, http.StatusTooManyRequests, "daily_cap", "demo run budget for today is used up")
		return
	}
	s.dayRuns++
	sess.RunStarts = append(sess.RunStarts, time.Now())
	sess.Run = &RunState{ID: runID, Scenario: req.Scenario, Status: "starting", Started: time.Now()}
	sess.Events, sess.Context = nil, nil
	tenant := sess.Tenant
	s.mu.Unlock()

	fail := func(step string, err error) {
		s.mu.Lock()
		if sess.Run != nil && sess.Run.ID == runID {
			sess.Run.Status = "failed"
		}
		s.mu.Unlock()
		s.localEvent(sess, runID, "run.status", "error", step+" failed: "+err.Error())
		httpx.Fail(w, http.StatusBadGateway, "start_failed", step)
	}

	// 1. Harness mints a run-scoped workload identity. Web chose the run ID,
	//    so it derives the identity to delegate to itself rather than
	//    trusting the harness to report it.
	actor := pki.RunID(config.AgentType, runID)
	var created struct {
		SpiffeID string `json:"spiffe_id"`
	}
	if err := httpx.PostJSON(s.harness, config.HarnessURL+"/runs", nil,
		map[string]string{"tenant": tenant, "run_id": runID, "scenario": req.Scenario}, &created); err != nil {
		fail("create run", err)
		return
	}
	if created.SpiffeID != actor {
		fail("create run", fmt.Errorf("harness reported identity %q, expected %q", created.SpiffeID, actor))
		return
	}

	// 2. The user delegates ticket:create on ENG to that run identity.
	var dlg struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := httpx.PostJSON(s.grants, config.GrantsURL+"/delegations", nil, map[string]any{
		"tenant": tenant, "subject": config.Subject, "actor": actor,
		"scope": []string{"ticket:create"}, "project": config.Project, "ttl_seconds": int(delegationTTL.Seconds()),
	}, &dlg); err != nil {
		fail("create delegation", err)
		return
	}
	s.mu.Lock()
	if sess.Run != nil && sess.Run.ID == runID {
		sess.Run.SpiffeID, sess.Run.DelegationID, sess.Run.DelegationExp = actor, dlg.ID, dlg.ExpiresAt
	}
	current := sess.Run != nil && sess.Run.ID == runID
	var snap RunState
	if current {
		snap = *sess.Run
	}
	s.mu.Unlock()
	if !current {
		// Reset landed while we were starting: don't launch an orphaned run.
		_ = httpx.PostJSON(s.harness, config.HarnessURL+"/runs/"+runID+"/cancel", nil, struct{}{}, nil)
		httpx.Fail(w, http.StatusConflict, "reset_during_start", "")
		return
	}
	s.localEvent(sess, runID, "user.delegate", "info", fmt.Sprintf("%s delegated ticket:create on %s to run/%s as %s (expires %s)",
		config.Subject, config.Project, runID, dlg.ID, dlg.ExpiresAt.Format("15:04:05")))

	// 3. Harness starts the agent with the delegation ID (useless without the run's key).
	if err := httpx.PostJSON(s.harness, config.HarnessURL+"/runs/"+runID+"/start", nil,
		map[string]string{"delegation_id": dlg.ID}, nil); err != nil {
		fail("start run", err)
		return
	}
	if req.Scenario == "revoke" || req.Scenario == "expire" {
		go s.watchFirstTicket(sess, snap)
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"run_id": runID})
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.mu.Lock()
	run := sess.Run
	sess.Run, sess.Events, sess.Context = nil, nil, nil
	tenant := sess.Tenant
	s.mu.Unlock()
	if run != nil {
		_ = httpx.PostJSON(s.harness, config.HarnessURL+"/runs/"+run.ID+"/cancel", nil, struct{}{}, nil)
	}
	_ = httpx.PostJSON(s.grants, config.GrantsURL+"/tenants/"+tenant+"/reset", nil, struct{}{}, nil)
	_ = httpx.PostJSON(s.jira, config.JiraURL+"/internal/tenants/"+tenant+"/reset", nil, struct{}{}, nil)
	w.WriteHeader(http.StatusNoContent)
}

func mustSub(fsys embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
