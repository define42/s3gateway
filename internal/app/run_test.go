package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/splunkhec"
)

type listenerError struct {
	err        error
	closeCalls atomic.Int32
}

func (l *listenerError) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l *listenerError) Close() error {
	l.closeCalls.Add(1)
	return nil
}

func (l *listenerError) Addr() net.Addr {
	return staticAddr("test-listener")
}

type staticAddr string

func (a staticAddr) Network() string { return "test" }
func (a staticAddr) String() string  { return string(a) }

type notifyingListener struct {
	net.Listener
	accepting chan struct{}
	once      sync.Once
}

func (l *notifyingListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.accepting) })
	return l.Listener.Accept()
}

func baseRunDependencies(signalCtx context.Context) runDependencies {
	return runDependencies{
		loadConfig: func() config.Config {
			return config.Config{}
		},
		configureLogging: configureSplunkLogging,
		boot: func(config.Config) (*http.Server, func(), error) {
			return &http.Server{}, func() {}, nil
		},
		listen: func(*http.Server, config.Config) (net.Listener, bool, error) {
			return &listenerError{err: errors.New("serve failed")}, false, nil
		},
		notifyContext: func(context.Context, ...os.Signal) (context.Context, context.CancelFunc) {
			return signalCtx, func() {}
		},
	}
}

func restoreDefaultLogger(t *testing.T) {
	t.Helper()
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
}

func TestDefaultRunDependencies(t *testing.T) {
	dependencies := defaultRunDependencies()
	if dependencies.loadConfig == nil || dependencies.configureLogging == nil ||
		dependencies.boot == nil || dependencies.listen == nil || dependencies.notifyContext == nil {
		t.Fatal("default run dependencies contain a nil function")
	}
}

func TestRunReturnsFailureForInitializationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*runDependencies)
	}{
		{
			name: "logging configuration",
			mutate: func(dependencies *runDependencies) {
				dependencies.configureLogging = func(config.Config, slog.Handler) (*splunkhec.Handler, error) {
					return nil, errors.New("logging failed")
				}
			},
		},
		{
			name: "application boot",
			mutate: func(dependencies *runDependencies) {
				dependencies.boot = func(config.Config) (*http.Server, func(), error) {
					return nil, func() {}, errors.New("boot failed")
				}
			},
		},
		{
			name: "listener creation",
			mutate: func(dependencies *runDependencies) {
				dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
					return nil, false, errors.New("listen failed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreDefaultLogger(t)
			dependencies := baseRunDependencies(t.Context())
			tt.mutate(&dependencies)

			if exitCode := run(dependencies); exitCode != 1 {
				t.Fatalf("run() exit code = %d, want 1", exitCode)
			}
		})
	}
}

func TestRunReturnsFailureWhenServerFails(t *testing.T) {
	restoreDefaultLogger(t)
	serveErr := errors.New("accept failed")
	dependencies := baseRunDependencies(t.Context())
	dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
		return &listenerError{err: serveErr}, false, nil
	}

	if exitCode := run(dependencies); exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
}

func TestRunShutsDownAndCleansUpOnSignal(t *testing.T) {
	restoreDefaultLogger(t)
	signalCtx, sendSignal := context.WithCancel(t.Context())
	dependencies := baseRunDependencies(signalCtx)
	serverAccepting := make(chan struct{})
	var cleanupCalls atomic.Int32
	dependencies.boot = func(config.Config) (*http.Server, func(), error) {
		return &http.Server{}, func() { cleanupCalls.Add(1) }, nil
	}
	dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, false, err
		}
		return &notifyingListener{
			Listener:  listener,
			accepting: serverAccepting,
		}, false, nil
	}

	done := make(chan int, 1)
	go func() {
		done <- run(dependencies)
	}()
	<-serverAccepting
	sendSignal()

	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("run() exit code = %d, want 0", exitCode)
		}
	case <-time.After(time.Second):
		t.Fatal("run() did not stop after shutdown signal")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestRunClosesListenerWhenSignalPrecedesServing(t *testing.T) {
	restoreDefaultLogger(t)
	signalCtx, sendSignal := context.WithCancel(t.Context())
	sendSignal()
	listener := &listenerError{err: errors.New("must not serve")}
	dependencies := baseRunDependencies(signalCtx)
	dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
		return listener, false, nil
	}

	if exitCode := run(dependencies); exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener close calls = %d, want 1", got)
	}
}

func TestListenForGatewayHTTP(t *testing.T) {
	listener, isTLS, err := listenForGateway(&http.Server{Addr: "127.0.0.1:0"}, config.Config{})
	if err != nil {
		t.Fatalf("listenForGateway() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if isTLS {
		t.Fatal("HTTP listener reported TLS")
	}
}

func TestListenForGatewayRejectsEmptyACMEDomains(t *testing.T) {
	_, _, err := listenForGateway(&http.Server{}, config.Config{AcmeDomains: " , "})
	if err == nil {
		t.Fatal("listenForGateway() error = nil, want invalid ACME domains")
	}
}

func TestListenForGatewayReportsACMECertificateReadFailure(t *testing.T) {
	restoreCertmagicGlobals(t)
	_, _, err := listenForGateway(&http.Server{}, config.Config{
		AcmeDomains: "gateway.example.com",
		AcmeCaDir:   t.TempDir() + "/missing",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to read ACME CA certificates") {
		t.Fatalf("listenForGateway() error = %v, want certificate read failure", err)
	}
}

func TestListenForGatewayACME(t *testing.T) {
	restoreCertmagicGlobals(t)
	listener := &listenerError{err: errors.New("not serving")}
	trustedRoots := x509.NewCertPool()
	var gotDomains []string
	dependencies := gatewayListenDependencies{
		listenTCP: func(string, string) (net.Listener, error) {
			t.Fatal("TCP listener called for ACME configuration")
			return nil, nil
		},
		readCertificates: func(path string) (*x509.CertPool, error) {
			if path != "/test/ca" {
				t.Fatalf("certificate path = %q, want /test/ca", path)
			}
			return trustedRoots, nil
		},
		listenTLS: func(domains []string) (net.Listener, error) {
			gotDomains = append([]string(nil), domains...)
			return listener, nil
		},
	}

	got, isTLS, err := listenForGatewayWith(&http.Server{}, config.Config{
		AcmeDomains: " gateway.example.com, , admin.example.com ",
		AcmeCaDir:   "/test/ca",
		AcmeDataDir: "/test/data",
		AcmeServer:  "https://acme.example/directory",
	}, dependencies)
	if err != nil {
		t.Fatalf("listenForGatewayWith() error = %v", err)
	}
	if got != listener || !isTLS {
		t.Fatalf("listener = %v, TLS = %t, want fake TLS listener", got, isTLS)
	}
	wantDomains := []string{"gateway.example.com", "admin.example.com"}
	if !slices.Equal(gotDomains, wantDomains) {
		t.Fatalf("ACME domains = %v, want %v", gotDomains, wantDomains)
	}
	storage, ok := certmagic.Default.Storage.(*certmagic.FileStorage)
	if !ok || storage.Path != "/test/data" {
		t.Fatalf("ACME storage = %#v, want /test/data file storage", certmagic.Default.Storage)
	}
	if !certmagic.DefaultACME.Agreed || certmagic.DefaultACME.TrustedRoots != trustedRoots ||
		certmagic.DefaultACME.CA != "https://acme.example/directory" {
		t.Fatal("ACME globals were not configured from the gateway config")
	}
}

func TestListenForGatewayReportsListenerErrors(t *testing.T) {
	tcpErr := errors.New("TCP listen failed")
	_, _, err := listenForGatewayWith(&http.Server{}, config.Config{}, gatewayListenDependencies{
		listenTCP: func(string, string) (net.Listener, error) { return nil, tcpErr },
	})
	if !errors.Is(err, tcpErr) {
		t.Fatalf("HTTP listener error = %v, want wrapped %v", err, tcpErr)
	}

	restoreCertmagicGlobals(t)
	tlsErr := errors.New("TLS listen failed")
	_, _, err = listenForGatewayWith(&http.Server{}, config.Config{
		AcmeDomains: "gateway.example.com",
	}, gatewayListenDependencies{
		listenTLS: func([]string) (net.Listener, error) { return nil, tlsErr },
	})
	if !errors.Is(err, tlsErr) {
		t.Fatalf("ACME listener error = %v, want wrapped %v", err, tlsErr)
	}
}

func restoreCertmagicGlobals(t *testing.T) {
	t.Helper()
	previousAgreed := certmagic.DefaultACME.Agreed
	previousCA := certmagic.DefaultACME.CA
	previousRoots := certmagic.DefaultACME.TrustedRoots
	previousStorage := certmagic.Default.Storage
	t.Cleanup(func() {
		certmagic.DefaultACME.Agreed = previousAgreed
		certmagic.DefaultACME.CA = previousCA
		certmagic.DefaultACME.TrustedRoots = previousRoots
		certmagic.Default.Storage = previousStorage
	})
}

func TestConfigureSplunkLoggingDisabled(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	handler, err := configureSplunkLogging(config.Config{}, slog.NewJSONHandler(io.Discard, nil))
	if err != nil {
		t.Fatalf("configure disabled Splunk logging: %v", err)
	}
	if handler != nil {
		t.Fatal("disabled Splunk logging should not create a handler")
	}
}

func TestConfigureSplunkLoggingForwardsDefaultLogger(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	requests := make(chan []byte, 1)
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	var local bytes.Buffer
	handler, err := configureSplunkLogging(config.Config{
		SplunkHECEndpoint:      hecServer.URL,
		SplunkHECToken:         "test-token",
		SplunkHECIndex:         "gateway",
		SplunkHECFlushInterval: time.Hour,
	}, slog.NewJSONHandler(&local, nil))
	if err != nil {
		t.Fatalf("configure Splunk logging: %v", err)
	}
	slog.Info("configured logger event", "component", "app")

	closeSplunkLogging(handler)
	if !bytes.Contains(local.Bytes(), []byte(`"msg":"configured logger event"`)) {
		t.Fatalf("local logger did not receive event: %s", local.Bytes())
	}
	select {
	case body := <-requests:
		if !bytes.Contains(body, []byte(`"index":"gateway"`)) ||
			!bytes.Contains(body, []byte(`"msg":"configured logger event"`)) {
			t.Fatalf("Splunk HEC batch mismatch: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Splunk HEC request")
	}
}

func TestBootAuditsAuthenticationFailures(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	httpServer, cleanup, err := boot(config.Config{
		LDAPURL:           "ldap://ldap.example:389",
		BaseDN:            "dc=example,dc=com",
		UpstreamEndpoint:  "https://s3.example",
		UpstreamRegion:    "us-east-1",
		UpstreamAccessKey: "access-key",
		UpstreamSecretKey: "secret-key",
		CookieSecret:      "1234567890abcdef1234567890abcdef",
		S3AuditHashKey:    "abcdef1234567890abcdef1234567890",
	})
	if err != nil {
		t.Fatalf("boot gateway: %v", err)
	}
	t.Cleanup(cleanup)

	r := httptest.NewRequest(http.MethodGet, "/private-bucket/private-key", nil)
	w := httptest.NewRecorder()
	httpServer.Handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status mismatch: got=%d want=%d", w.Code, http.StatusUnauthorized)
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"event_kind":"s3_audit"`)) ||
		!bytes.Contains(logs.Bytes(), []byte(`"action":"GetObject"`)) {
		t.Fatalf("booted handler did not emit an S3 audit event: %s", logs.Bytes())
	}
	if bytes.Contains(logs.Bytes(), []byte("private-bucket")) ||
		bytes.Contains(logs.Bytes(), []byte("private-key")) {
		t.Fatalf("booted handler exposed resource names: %s", logs.Bytes())
	}
}
