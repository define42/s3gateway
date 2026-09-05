package upstream

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/define42/s3gateway/internal/config"
)

func testConfig(endpoint string) config.Config {
	return config.Config{
		UpstreamEndpoint:       endpoint,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "test-access-key",
		UpstreamSecretKey:      "test-secret-key",
		UpstreamForcePathStyle: true,
	}
}

func isolateAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_CA_BUNDLE", "")
}

func trustTestServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", path)
}

func TestNewRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "http://s3.example", "s3.example", "https:///s3"} {
		t.Run(endpoint, func(t *testing.T) {
			for _, skipValidation := range []bool{false, true} {
				cfg := testConfig(endpoint)
				cfg.UpstreamSkipCertificateValidation = skipValidation
				client, err := New(t.Context(), cfg)
				if err == nil || !strings.Contains(err.Error(), "S3_ENDPOINT") {
					t.Fatalf("skip validation=%t: New error = %v, want S3_ENDPOINT validation error", skipValidation, err)
				}
				if client != nil {
					t.Fatal("invalid endpoint returned an S3 client")
				}
			}
		})
	}
}

func TestNewVerifiesUpstreamCertificate(t *testing.T) {
	isolateAWSConfig(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	for _, tt := range []struct {
		name           string
		skipValidation bool
	}{
		{name: "untrusted certificate rejected by default"},
		{name: "explicit skip accepts untrusted certificate", skipValidation: true},
		{name: "disabled client remains strict after enabled client"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(server.URL)
			cfg.UpstreamSkipCertificateValidation = tt.skipValidation
			client, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Options().HTTPClient.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !tt.skipValidation {
				if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
					t.Fatalf("request error = %v, want unknown certificate authority", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("request with certificate validation explicitly disabled: %v", err)
			}
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", resp.StatusCode)
			}
		})
	}

	t.Run("AWS_CA_BUNDLE trusted", func(t *testing.T) {
		trustTestServer(t, server)
		client, err := New(t.Context(), testConfig(server.URL))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Options().HTTPClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", resp.StatusCode)
		}
	})
}

func TestNewRejectsHTTPSRedirectDowngrade(t *testing.T) {
	isolateAWSConfig(t)
	var insecureRequests atomic.Int32
	insecureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		insecureRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(insecureServer.Close)
	secureServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, err := strconv.Atoi(r.URL.Query().Get("status"))
		if err != nil {
			t.Errorf("invalid redirect status: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, insecureServer.URL, status)
	}))
	t.Cleanup(secureServer.Close)
	for _, skipValidation := range []bool{false, true} {
		t.Run("skip_validation="+strconv.FormatBool(skipValidation), func(t *testing.T) {
			if !skipValidation {
				trustTestServer(t, secureServer)
			}
			cfg := testConfig(secureServer.URL)
			cfg.UpstreamSkipCertificateValidation = skipValidation
			client, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range []int{301, 302, 303, 307, 308} {
				t.Run(strconv.Itoa(status), func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
						secureServer.URL+"?status="+strconv.Itoa(status), strings.NewReader("private object"))
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Options().HTTPClient.Do(req)
					if resp != nil {
						_ = resp.Body.Close()
					}
					if err == nil || !strings.Contains(err.Error(), "redirect must use HTTPS") {
						t.Fatalf("request error = %v, want rejected HTTPS downgrade", err)
					}
					if got := insecureRequests.Load(); got != 0 {
						t.Fatalf("plaintext server received %d requests", got)
					}
				})
			}
		})
	}
}

func TestNewAllowsHTTPSRedirectWithLimit(t *testing.T) {
	isolateAWSConfig(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/done", http.StatusTemporaryRedirect)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	trustTestServer(t, server)
	client, err := New(t.Context(), testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/redirect", "/loop"} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Options().HTTPClient.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if path == "/loop" {
				if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
					t.Fatalf("request error = %v, want redirect limit", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 after HTTPS redirect", resp.StatusCode)
			}
		})
	}
}
