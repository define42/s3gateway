package main

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

	"github.com/caddyserver/certmagic"
	"github.com/define42/s3gateway/internal/certreader"
	"github.com/define42/s3gateway/internal/handler"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	httpSrv, cfg, err := handler.BootS3Gateway()
	if err != nil {
		slog.Error("failed to boot s3 gateway", "error", err)
		os.Exit(1)
	}

	serverErr := make(chan error, 1)

	// will hold the TLS listener if ACME is enabled
	var tlsLn net.Listener

	go func() {
		sent := false
		sendServerErr := func(err error) {
			if sent {
				return
			}
			serverErr <- err
			sent = true
		}

		// Ensure we always signal back (prevents deadlocks)
		defer func() {
			sendServerErr(nil)
		}()

		if strings.TrimSpace(cfg.AcmeDomains) != "" {
			slog.Info("starting ACME certificate manager", "domains", cfg.AcmeDomains)

			raw := strings.Split(cfg.AcmeDomains, ",")
			domains := make([]string, 0, len(raw))
			for _, d := range raw {
				d = strings.TrimSpace(d)
				if d != "" {
					domains = append(domains, d)
				}
			}
			if len(domains) == 0 {
				sendServerErr(fmt.Errorf("no valid ACME domains provided"))
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

			ln, err := certmagic.Listen(domains)
			if err != nil {
				sendServerErr(fmt.Errorf("ACME listen error: %w", err))
				return
			}
			tlsLn = ln

			slog.Info("starting HTTPS server", "addr", ln.Addr().String())
			err = httpSrv.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				sendServerErr(fmt.Errorf("https server error: %w", err))
				return
			}

			// normal shutdown
			sendServerErr(nil)
			return
		}

		slog.Info("starting HTTP server", "addr", httpSrv.Addr)
		err := httpSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			sendServerErr(fmt.Errorf("http server error: %w", err))
			return
		}
		sendServerErr(nil)
	}()

	shutdownSignalsCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
		return
	case <-shutdownSignalsCtx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), handler.EffectiveShutdownTimeout(cfg))
	defer cancel()

	// Important: close the listener to unblock Serve(ln)
	if tlsLn != nil {
		_ = tlsLn.Close()
	}

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown failed", "error", err)
		_ = httpSrv.Close()
	}

	// Wait for goroutine to finish
	if err := <-serverErr; err != nil {
		slog.Error("server shutdown error", "error", err)
		os.Exit(1)
	}
}
