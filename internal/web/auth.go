package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"agentbroker/internal/httpx"
)

// The password gate is a thin deterrent in front of the public dashboard,
// not an identity system: everyone shares one password.

const authCookie = "demo_auth"

//go:embed login.html
var loginPage []byte

type gate struct {
	password string
	token    string // cookie value proving the password was entered
}

// newGate derives the cookie value from the password, so it survives
// restarts, can't be forged without the password, and changing the password
// signs everyone out.
func newGate(password string) *gate {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("agent-broker demo auth v1"))
	return &gate{password: password, token: hex.EncodeToString(mac.Sum(nil))}
}

func (g *gate) authed(r *http.Request) bool {
	c, err := r.Cookie(authCookie)
	return err == nil && hmac.Equal([]byte(c.Value), []byte(g.token))
}

// wrap lets through /login, /healthz and authenticated requests. Others get
// a 401 (API) or a redirect to the login page.
func (g *gate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			g.login(w, r)
		case r.URL.Path == "/healthz" || g.authed(r):
			next.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/"):
			httpx.Fail(w, http.StatusUnauthorized, "unauthenticated", "")
		default:
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})
}

func (g *gate) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if g.authed(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(loginPage)
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		pw := r.PostFormValue("password")
		if subtle.ConstantTimeCompare([]byte(pw), []byte(g.password)) != 1 {
			time.Sleep(time.Second) // slows guessing
			http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: authCookie, Value: g.token, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
