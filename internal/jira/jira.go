// Package jira is a tiny stand-in for an external ticketing API. It accepts
// writes only with the broker's API key.
package jira

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/httpx"
)

type Issue struct {
	Key        string    `json:"key"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Reporter   string    `json:"reporter"`
	OnBehalfOf string    `json:"on_behalf_of"`
	RunID      string    `json:"run_id"`
	Created    time.Time `json:"created"`
	Replayed   bool      `json:"replayed,omitempty"` // response only: request matched an earlier Idempotency-Key
}

type store struct {
	apiKey string
	mu     sync.Mutex
	issues map[string][]Issue        // tenant -> issues
	idem   map[string]map[string]int // tenant -> Idempotency-Key -> index into issues
}

func Main() {
	key, err := os.ReadFile(filepath.Join(config.PKIDir(), "jira", "jira.key"))
	if err != nil {
		log.Fatal(err)
	}
	s := &store{apiKey: strings.TrimSpace(string(key)), issues: map[string][]Issue{}, idem: map[string]map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /rest/api/issue", s.create)
	// Read-only listing for the dashboard; bound to localhost only.
	mux.HandleFunc("GET /internal/issues", s.list)
	mux.HandleFunc("POST /internal/tenants/{tenant}/reset", s.reset)
	httpx.Serve("jira", &http.Server{Addr: config.JiraAddr, Handler: mux}, false)
}

func (s *store) create(w http.ResponseWriter, r *http.Request) {
	got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.apiKey)) != 1 {
		httpx.Fail(w, http.StatusUnauthorized, "unauthorized", "")
		return
	}
	tenant := r.Header.Get("X-Tenant")
	var in Issue
	if err := httpx.ReadJSON(r, &in); err != nil || tenant == "" {
		httpx.Fail(w, http.StatusBadRequest, "bad_request", "")
		return
	}
	idemKey := r.Header.Get("Idempotency-Key")
	s.mu.Lock()
	defer s.mu.Unlock()
	// A retried request returns the ticket the first attempt created.
	if i, ok := s.idem[tenant][idemKey]; ok && idemKey != "" {
		prev := s.issues[tenant][i]
		prev.Replayed = true
		httpx.WriteJSON(w, http.StatusOK, prev)
		return
	}
	in.Key = fmt.Sprintf("%s-%d", config.Project, len(s.issues[tenant])+1)
	in.Created = time.Now()
	in.Replayed = false
	s.issues[tenant] = append(s.issues[tenant], in)
	if idemKey != "" {
		if s.idem[tenant] == nil {
			s.idem[tenant] = map[string]int{}
		}
		s.idem[tenant][idemKey] = len(s.issues[tenant]) - 1
	}
	httpx.WriteJSON(w, http.StatusCreated, in)
}

func (s *store) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	out := append([]Issue{}, s.issues[r.URL.Query().Get("tenant")]...)
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *store) reset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	delete(s.issues, r.PathValue("tenant"))
	delete(s.idem, r.PathValue("tenant"))
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
