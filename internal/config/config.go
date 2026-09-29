// Package config holds the demo's topology. Defaults describe the
// single-host layout (`demo supervise`, everything on localhost); the
// Compose file overrides them so each service runs in its own container.
package config

import "os"

var (
	// Listen addresses.
	GrantsAddr  = Env("GRANTS_LISTEN", "127.0.0.1:9001")
	BrokerAddr  = Env("BROKER_LISTEN", "127.0.0.1:9002")
	HarnessAddr = Env("HARNESS_LISTEN", "127.0.0.1:9003")
	JiraAddr    = Env("JIRA_LISTEN", "127.0.0.1:9004")
	EventsAddr  = Env("EVENTS_LISTEN", "127.0.0.1:9000")

	// Where each service is reached. Servers are authenticated by SPIFFE ID,
	// not hostname, so these only need to resolve.
	GrantsURL  = Env("GRANTS_URL", "https://localhost:9001")
	BrokerURL  = Env("BROKER_URL", "https://localhost:9002")
	HarnessURL = Env("HARNESS_URL", "https://localhost:9003")
	JiraURL    = Env("JIRA_URL", "http://127.0.0.1:9004")
	EventsURL  = Env("EVENTS_URL", "http://127.0.0.1:9000")
)

const (
	AgentType = "code-reviewer"
	Project   = "ENG"
	Subject   = "alice@demo"
)

// PKIDir is where each service finds its key material (<PKIDir>/<service>/).
func PKIDir() string { return Env("PKI_DIR", "./run/pki") }

func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
