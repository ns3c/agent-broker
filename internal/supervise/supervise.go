// Package supervise bootstraps the demo container: it generates the CA and
// per-service key material, then runs each service as its own process with
// only the secrets that service needs.
package supervise

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agentbroker/internal/config"
	"agentbroker/internal/pki"
)

// Start order matters only for tidiness; clients retry.
var services = []string{"jira", "grants", "broker", "harness", "web"}

func Main() {
	dir := config.PKIDir()
	if err := generate(dir); err != nil {
		log.Fatalf("pki: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exited := make(chan string)
	for _, svc := range services {
		cmd := exec.Command(self, svc)
		cmd.Env = envFor(svc)
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			log.Fatalf("start %s: %v", svc, err)
		}
		go prefix(svc, stdout)
		go func() { _ = cmd.Wait(); exited <- svc }()
		time.Sleep(150 * time.Millisecond)
	}
	// If any service dies, exit so the platform restarts the whole container.
	log.Fatalf("%s exited; shutting down", <-exited)
}

// envFor strips the Anthropic API key from every process except the harness.
func envFor(svc string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") && svc != "harness" {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func prefix(svc string, r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fmt.Printf("%-8s| %s\n", svc, sc.Text())
	}
}

// Init generates key material and exits. Compose runs it as a one-shot
// container before the services start.
// Existing material is kept so that restarting the stack doesn't leave
// running services holding keys that no longer match; `docker compose
// down -v` rotates everything.
func Init() {
	if _, err := os.Stat(filepath.Join(config.PKIDir(), "grants", "ca.key")); err == nil {
		log.Printf("pki already present in %s; keeping it", config.PKIDir())
		return
	}
	if err := generate(config.PKIDir()); err != nil {
		log.Fatalf("pki: %v", err)
	}
	log.Printf("pki written to %s", config.PKIDir())
}

// generate writes a fresh PKI on every boot. Each service directory is
// self-contained and holds only what that service needs, so it can be
// mounted into that service's container alone:
//
//	<svc>/ca.crt                 trust bundle (public)
//	<svc>/svc.{crt,key}          service identity
//	grants/ca.key, signing.key   run-identity CA and token signing key
//	broker/signing.pub, jira.key token verification key and the Jira credential
//	jira/jira.key                the key Jira expects
func generate(dir string) error {
	// Remove only what a previous boot wrote, never the directory itself.
	for _, name := range []string{"web", "grants", "broker", "harness", "jira"} {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	ca, err := pki.NewCA()
	if err != nil {
		return err
	}
	for _, svc := range []string{"web", "grants", "broker", "harness"} {
		key, err := pki.NewKey()
		if err != nil {
			return err
		}
		// Server certs name both the Compose hostname and localhost, so the
		// same PKI works in containers and under `demo supervise`.
		cert, err := ca.Issue(pki.ServiceID(svc), key.Public(), pki.CertLifetime, "localhost", svc)
		if err != nil {
			return err
		}
		if err := pki.WriteCertPEM(filepath.Join(dir, svc, "ca.crt"), ca.Cert); err != nil {
			return err
		}
		if err := pki.WriteCertPEM(filepath.Join(dir, svc, "svc.crt"), cert); err != nil {
			return err
		}
		if err := pki.WriteKeyPEM(filepath.Join(dir, svc, "svc.key"), key); err != nil {
			return err
		}
	}

	if err := pki.WriteKeyPEM(filepath.Join(dir, "grants", "ca.key"), ca.Key); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := pki.WriteKeyPEM(filepath.Join(dir, "grants", "signing.key"), priv); err != nil {
		return err
	}
	if err := pki.WritePublicKeyPEM(filepath.Join(dir, "broker", "signing.pub"), pub); err != nil {
		return err
	}

	jiraKey := []byte("jira_" + pki.RandomHex(16))
	for _, p := range []string{filepath.Join(dir, "broker", "jira.key"), filepath.Join(dir, "jira", "jira.key")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, jiraKey, 0o600); err != nil {
			return err
		}
	}
	return nil
}
