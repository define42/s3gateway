package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/define42/s3gateway/internal/certreader"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/server"
	"github.com/define42/s3gateway/internal/splunkhec"
)

const splunkHECCloseTimeout = 10 * time.Second

type runDependencies struct {
	loadConfig       func() config.Config
	configureLogging func(config.Config, slog.Handler) (*splunkhec.Handler, error)
	boot             func(config.Config) (*http.Server, contextCleanup, error)
	listen           func(*http.Server, config.Config) (net.Listener, bool, error)
	notifyContext    func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
}

func defaultRunDependencies() runDependencies {
	return runDependencies{
		loadConfig:       config.LoadConfig,
		configureLogging: configureSplunkLogging,
		boot:             bootWithContextCleanup,
		listen:           listenForGateway,
		notifyContext:    signal.NotifyContext,
	}
}

// Run starts the configured HTTP or ACME-managed HTTPS server, waits for a
// server failure or termination signal, and performs a bounded graceful
// shutdown. It returns 0 after a clean server stop and 1 when initialization or
// serving reports an error.
func Run() int {
	return run(defaultRunDependencies())
}

func run(dependencies runDependencies) int {
	localHandler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(localHandler))

	cfg := dependencies.loadConfig()
	splunkHandler, err := dependencies.configureLogging(cfg, localHandler)
	if err != nil {
		slog.Error("failed to configure Splunk HEC logging", "error", err)
		return 1
	}
	if splunkHandler != nil {
		defer closeSplunkLogging(splunkHandler)
	}

	httpServer, cleanup, err := dependencies.boot(cfg)
	if err != nil {
		slog.Error("failed to boot s3 gateway", "error", err)
		return 1
	}
	// Shared clients remain available while HTTP requests drain. Startup
	// failures use a fresh cleanup budget; normal shutdown shares the HTTP one.
	cleanupDone := false
	closeDependencies := func(ctx context.Context) {
		cleanupDone = true
		if err := cleanup(ctx); err != nil {
			slog.Warn("Kafka cleanup did not complete gracefully", "error", err)
		}
	}
	defer func() {
		if cleanupDone {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), server.EffectiveShutdownTimeout(cfg))
		defer cancel()
		closeDependencies(ctx)
	}()

	shutdownSignalsCtx, stop := dependencies.notifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	listener, isTLS, err := dependencies.listen(httpServer, cfg)
	if err != nil {
		slog.Error("failed to listen", "error", err)
		return 1
	}
	if shutdownSignalsCtx.Err() != nil {
		_ = listener.Close()
		return 0
	}

	protocol := "HTTP"
	if isTLS {
		protocol = "HTTPS"
	}
	slog.Info("starting "+protocol+" server", "addr", listener.Addr().String())

	serverErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("%s server error: %w", strings.ToLower(protocol), err)
			return
		}
		serverErr <- nil
	}()

	exitCode := 0
	select {
	case err := <-serverErr:
		serverErr = nil
		if err != nil {
			slog.Error("server error", "error", err)
			exitCode = 1
		}
	case <-shutdownSignalsCtx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		server.EffectiveShutdownTimeout(cfg),
	)

	defer cancel()
	defer func() { closeDependencies(shutdownCtx) }()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown failed", "error", err)
		_ = httpServer.Close()
	}

	if serverErr != nil {
		if err := <-serverErr; err != nil {
			slog.Error("server shutdown error", "error", err)
			exitCode = 1
		}
	}
	return exitCode
}

func listenForGateway(httpServer *http.Server, cfg config.Config) (net.Listener, bool, error) {
	return listenForGatewayWith(httpServer, cfg, gatewayListenDependencies{
		listenTCP:        net.Listen,
		readCertificates: certreader.ReadCertificates,
		listenTLS:        certmagic.Listen,
	})
}

type gatewayListenDependencies struct {
	listenTCP        func(network, address string) (net.Listener, error)
	readCertificates func(string) (*x509.CertPool, error)
	listenTLS        func([]string) (net.Listener, error)
}

func listenForGatewayWith(
	httpServer *http.Server,
	cfg config.Config,
	dependencies gatewayListenDependencies,
) (net.Listener, bool, error) {
	if strings.TrimSpace(cfg.AcmeDomains) == "" {
		addr := httpServer.Addr
		if addr == "" {
			addr = ":http"
		}
		listener, err := dependencies.listenTCP("tcp", addr)
		if err != nil {
			return nil, false, fmt.Errorf("listen for HTTP traffic: %w", err)
		}
		return listener, false, nil
	}

	rawDomains := strings.Split(cfg.AcmeDomains, ",")
	domains := make([]string, 0, len(rawDomains))
	for _, domain := range rawDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if len(domains) == 0 {
		return nil, false, errors.New("no valid ACME domains provided")
	}

	slog.Info("starting ACME certificate manager", "domains", cfg.AcmeDomains)
	certmagic.DefaultACME.Agreed = true
	certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.AcmeDataDir}
	if cfg.AcmeCaDir != "" {
		privateCA, err := dependencies.readCertificates(cfg.AcmeCaDir)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read ACME CA certificates: %w", err)
		}
		certmagic.DefaultACME.TrustedRoots = privateCA
	}
	certmagic.DefaultACME.CA = cfg.AcmeServer

	listener, err := dependencies.listenTLS(domains)
	if err != nil {
		return nil, false, fmt.Errorf("ACME listen error: %w", err)
	}
	return listener, true, nil
}

func configureSplunkLogging(cfg config.Config, localHandler slog.Handler) (*splunkhec.Handler, error) {
	if cfg.SplunkHECEndpoint == "" {
		return nil, nil
	}
	handler, err := splunkhec.NewHandler(splunkhec.Options{
		Endpoint:      cfg.SplunkHECEndpoint,
		Token:         cfg.SplunkHECToken,
		Index:         cfg.SplunkHECIndex,
		FlushInterval: cfg.SplunkHECFlushInterval,
		LocalHandler:  localHandler,
		ErrorWriter:   os.Stderr,
	})
	if err != nil {
		return nil, fmt.Errorf("creating Splunk HEC log handler: %w", err)
	}
	slog.SetDefault(slog.New(handler))
	return handler, nil
}

func closeSplunkLogging(handler *splunkhec.Handler) {
	ctx, cancel := context.WithTimeout(context.Background(), splunkHECCloseTimeout)
	defer cancel()
	if err := handler.Close(ctx); err != nil {
		slog.Warn("failed to flush logs to Splunk HEC during shutdown", "error", err)
	}
}
