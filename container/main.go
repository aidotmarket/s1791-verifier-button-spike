// Spike binary for the S1791 Cloudflare one-click test. No data access.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

//go:embed roots/*.pem
var roots embed.FS

var pins = map[string]bool{
	"0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3": true,
	"762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332": true,
	"b0292ae545978e0fbb98abbd94c861605e5b18bb32ed523f50d5b7b5c71d47bc": true,
	"7e4e8838a8add6295de7ae3b047d3aba3488ab95db0a0aa56d897a00d8618bcf": true,
}

func pool() *x509.CertPool {
	p := x509.NewCertPool()
	ents, _ := roots.ReadDir("roots")
	for _, e := range ents {
		b, _ := roots.ReadFile("roots/" + e.Name())
		p.AppendCertsFromPEM(b)
	}
	return p
}

func tlsCheck(host string) map[string]any {
	out := map[string]any{"host": host}
	var seen []string
	c := &http.Client{Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect_refused") },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool(), ServerName: host,
			VerifyConnection: func(s tls.ConnectionState) error {
				for _, pc := range s.PeerCertificates {
					seen = append(seen, pc.Subject.CommonName+" <- "+pc.Issuer.CommonName)
				}
				for _, ch := range s.VerifiedChains {
					h := sha256.Sum256(ch[len(ch)-1].RawSubjectPublicKeyInfo)
					hx := hex.EncodeToString(h[:])
					out["root_spki"] = hx
					if pins[hx] {
						return nil
					}
				}
				return errors.New("tls_pin_mismatch")
			}},
			DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}}
	r, err := c.Get("https://" + host + "/health")
	out["peer_chain"] = seen
	if err != nil {
		out["ok"] = false
		out["error"] = err.Error()
		return out
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 512))
	out["ok"] = true
	out["status"] = r.StatusCode
	out["body_prefix"] = string(b[:min(len(b), 80)])
	return out
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"spike": "s1791-cf-button", "pid": os.Getpid(), "time": time.Now().UTC()})
	})
	http.HandleFunc("/tls-check", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"allowed":     tlsCheck("api.ai.market"),
			"not_allowed": tlsCheck("example.com"),
		})
	})
	http.ListenAndServe(":8080", nil)
}
