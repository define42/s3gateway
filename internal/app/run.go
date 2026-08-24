package app

import (
	"context"
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

// Run starts the gateway, waits for shutdown, and returns a process exit code.
func Run() int {
	localHandler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(localHandler))

	cfg := config.LoadConfig()
	splunkHandler, err := configureSplunkLogging(cfg, localHandler)
	if err != nil {
		slog.Error("failed to configure Splunk HEC logging", "error", err)
		return 1
	}
	if splunkHandler != nil {
		defer closeSplunkLogging(splunkHandler)
	}

	httpServer, cleanup, err := boot(cfg)
	if err != nil {
		slog.Error("failed to boot s3 gateway", "error", err)
		return 1
	}
	defer cleanup()

	serverErr := make(chan error, 1)

	// Will hold the TLS listener if ACME is enabled.
	var tlsListener net.Listener

	go func() {
		sent := false
		sendServerErr := func(err error) {
			if sent {
				return
			}
			serverErr <- err
			sent = true
		}

		// Ensure we always signal back to prevent deadlocks.
		defer func() {
			sendServerErr(nil)
		}()

		if strings.TrimSpace(cfg.AcmeDomains) != "" {
			slog.Info("starting ACME certificate manager", "domains", cfg.AcmeDomains)

			rawDomains := strings.Split(cfg.AcmeDomains, ",")
			domains := make([]string, 0, len(rawDomains))
			for _, domain := range rawDomains {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					domains = append(domains, domain)
				}
			}
			if len(domains) == 0 {
				sendServerErr(errors.New("no valid ACME domains provided"))
				return
			}

			certmagic.DefaultACME.Agreed = true
			certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.AcmeDataDir}
			if cfg.AcmeCaDir != "" {
				privateCA, err := certreader.ReadCertificates(cfg.AcmeCaDir)
				if err != nil {
					sendServerErr(fmt.Errorf("failed to read ACME CA certificates: %w", err))
					return
				}
				certmagic.DefaultACME.TrustedRoots = privateCA
			}
			certmagic.DefaultACME.CA = cfg.AcmeServer

			listener, err := certmagic.Listen(domains)
			if err != nil {
				sendServerErr(fmt.Errorf("ACME listen error: %w", err))
				return
			}
			tlsListener = listener

			slog.Info("starting HTTPS server", "addr", listener.Addr().String())
			err = httpServer.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				sendServerErr(fmt.Errorf("https server error: %w", err))
				return
			}

			sendServerErr(nil)
			return
		}

		slog.Info("starting HTTP server", "addr", httpServer.Addr)
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			sendServerErr(fmt.Errorf("http server error: %w", err))
			return
		}
		sendServerErr(nil)
	}()

	shutdownSignalsCtx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil {
			slog.Error("server error", "error", err)
			return 1
		}
		return 0
	case <-shutdownSignalsCtx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		server.EffectiveShutdownTimeout(cfg),
	)
	defer cancel()

	// Close the listener to unblock Serve when ACME is enabled.
	if tlsListener != nil {
		_ = tlsListener.Close()
	}

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown failed", "error", err)
		_ = httpServer.Close()
	}

	if err := <-serverErr; err != nil {
		slog.Error("server shutdown error", "error", err)
		return 1
	}
	return 0
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
