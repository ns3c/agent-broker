// Package httpx holds small JSON-over-HTTP helpers shared by the services.
package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"agentbroker/internal/pki"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error is the body of every non-2xx response between services.
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func Fail(w http.ResponseWriter, status int, code, detail string) {
	WriteJSON(w, status, Error{Error: code, Detail: detail})
}

func ReadJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// RequirePeer wraps h so only callers presenting one of the allowed SPIFFE IDs get through.
func RequirePeer(h http.HandlerFunc, allowed ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peer := pki.PeerID(r)
		for _, a := range allowed {
			if peer == a {
				h(w, r)
				return
			}
		}
		Fail(w, http.StatusForbidden, "peer_not_allowed", peer)
	}
}

// StatusError is returned by PostJSON for non-2xx responses.
type StatusError struct {
	Status int
	Body   Error
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("http %d: %s", e.Status, e.Body.Error)
}

// PostJSON sends in as JSON and decodes a 2xx response into out.
// Transport failures are returned as-is; HTTP errors as *StatusError.
func PostJSON(c *http.Client, url string, headers map[string]string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		se := &StatusError{Status: resp.StatusCode}
		_ = json.NewDecoder(resp.Body).Decode(&se.Body)
		return se
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Serve runs srv and exits the process if it stops.
func Serve(name string, srv *http.Server, tls bool) {
	srv.ReadHeaderTimeout = 5 * time.Second
	log.Printf("%s listening on %s (mtls=%v)", name, srv.Addr, tls)
	var err error
	if tls {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	log.Fatalf("%s: %v", name, err)
}
