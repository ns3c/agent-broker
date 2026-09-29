// Package pki is the demo's stand-in for SPIFFE: a self-signed CA, X.509
// certificates carrying spiffe:// URI SANs, and mTLS configs that check them.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const TrustDomain = "demo.local"

// ServiceID returns the SPIFFE ID of a platform service.
func ServiceID(name string) string { return "spiffe://" + TrustDomain + "/svc/" + name }

// RunID returns the SPIFFE ID of one agent run.
func RunID(agentType, runID string) string {
	return "spiffe://" + TrustDomain + "/agent/" + agentType + "/run/" + runID
}

// ParseRunID splits spiffe://demo.local/agent/<type>/run/<id>.
func ParseRunID(spiffeID string) (agentType, runID string, ok bool) {
	rest, found := strings.CutPrefix(spiffeID, "spiffe://"+TrustDomain+"/agent/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "run" || parts[0] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[0], parts[2], true
}

// PeerID returns the SPIFFE ID of the verified client certificate on r.
func PeerID(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return CertID(r.TLS.PeerCertificates[0])
}

// CertID returns the first spiffe:// URI SAN of cert.
func CertID(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// ---- CA ----

type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "demo.local root CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		URIs:                  []*url.URL{mustURL("spiffe://" + TrustDomain)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issue signs pub into a leaf certificate for spiffeID. Only the public key
// crosses this boundary; the caller keeps the private key. Passing hostnames
// makes it a server certificate as well.
func (ca *CA) Issue(spiffeID string, pub crypto.PublicKey, ttl time.Duration, hostnames ...string) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustURL(spiffeID)},
	}
	if len(hostnames) > 0 {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		tmpl.DNSNames = hostnames
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ---- files ----

func WriteCertPEM(path string, cert *x509.Certificate) error {
	return writePEM(path, "CERTIFICATE", cert.Raw, 0o644)
}

func WriteKeyPEM(path string, key any) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func WritePublicKeyPEM(path string, pub any) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writePEM(path, "PUBLIC KEY", der, 0o644)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != typ {
		return nil, fmt.Errorf("%s: expected PEM %s", path, typ)
	}
	return blk.Bytes, nil
}

func LoadCert(path string) (*x509.Certificate, error) {
	der, err := readPEM(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func LoadKey(path string) (crypto.Signer, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}

func LoadEd25519Public(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 public key")
	}
	return pub, nil
}

func LoadCA(dir string) (*CA, error) {
	cert, err := LoadCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	key, err := LoadKey(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// ---- TLS ----

// Identity is a certificate + private key for one workload.
type Identity struct {
	ID    string
	TLS   tls.Certificate
	Roots *x509.CertPool
}

func NewIdentity(cert *x509.Certificate, key crypto.Signer, caCert *x509.Certificate) *Identity {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &Identity{
		ID:    CertID(cert),
		TLS:   tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert},
		Roots: roots,
	}
}

// Derive returns a new identity for cert/key that trusts the same roots.
func (id *Identity) Derive(cert *x509.Certificate, key crypto.Signer) *Identity {
	return &Identity{
		ID:    CertID(cert),
		TLS:   tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert},
		Roots: id.Roots,
	}
}

// LoadServiceIdentity reads <pkiDir>/<svc>/{ca.crt,svc.crt,svc.key}.
func LoadServiceIdentity(pkiDir, svc string) (*Identity, error) {
	ca, err := LoadCert(filepath.Join(pkiDir, svc, "ca.crt"))
	if err != nil {
		return nil, err
	}
	cert, err := LoadCert(filepath.Join(pkiDir, svc, "svc.crt"))
	if err != nil {
		return nil, err
	}
	key, err := LoadKey(filepath.Join(pkiDir, svc, "svc.key"))
	if err != nil {
		return nil, err
	}
	return NewIdentity(cert, key, ca), nil
}

// ServerTLS requires a client certificate chained to the demo CA.
// Authorization on the peer's SPIFFE ID is done per-handler.
func (id *Identity) ServerTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.TLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    id.Roots,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLS presents this identity and verifies the server is expectServer.
func (id *Identity) ClientTLS(expectServer string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.TLS},
		RootCAs:      id.Roots,
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if got := CertID(cs.PeerCertificates[0]); got != expectServer {
				return fmt.Errorf("server identity %q, want %q", got, expectServer)
			}
			return nil
		},
	}
}

// Client returns an HTTP client that speaks mTLS to expectServer.
func (id *Identity) Client(expectServer string) *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: id.ClientTLS(expectServer)},
	}
}

// NewKey generates a workload keypair (ECDSA P-256).
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// RandomHex returns n random bytes hex-encoded.
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
