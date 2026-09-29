package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGate(t *testing.T) {
	g := newGate("agent-broker")
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("app")) }))
	do := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := do("GET", "/", "", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("page without auth: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := do("GET", "/api/state", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("api without auth: %d", w.Code)
	}
	if w := do("GET", "/healthz", "", nil); w.Code != http.StatusOK {
		t.Fatalf("healthz must stay open: %d", w.Code)
	}
	if w := do("GET", "/", "", &http.Cookie{Name: authCookie, Value: "forged"}); w.Code != http.StatusSeeOther {
		t.Fatalf("forged cookie accepted: %d", w.Code)
	}
	if w := do("POST", "/login", "password=wrong", nil); w.Header().Get("Location") != "/login?error=1" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("wrong password: %q, cookies %v", w.Header().Get("Location"), w.Result().Cookies())
	}

	w := do("POST", "/login", "password="+url.QueryEscape("agent-broker"), nil)
	cookies := w.Result().Cookies()
	if w.Header().Get("Location") != "/" || len(cookies) != 1 || cookies[0].MaxAge <= 0 || !cookies[0].HttpOnly {
		t.Fatalf("right password: %q, cookies %v", w.Header().Get("Location"), cookies)
	}
	if w := do("GET", "/api/state", "", cookies[0]); w.Code != http.StatusOK || w.Body.String() != "app" {
		t.Fatalf("with auth cookie: %d %q", w.Code, w.Body.String())
	}
	// Survives a restart: a fresh gate with the same password accepts the cookie.
	if !newGate("agent-broker").authed(httptestReq(cookies[0])) {
		t.Fatal("cookie rejected after restart")
	}
	if newGate("rotated").authed(httptestReq(cookies[0])) {
		t.Fatal("cookie must stop working when the password changes")
	}
}

func httptestReq(c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	return r
}
