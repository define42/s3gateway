package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func EffectiveShutdownTimeout(cfg config.Config) time.Duration {
	cfg.ApplyDefaults()
	return cfg.ShutdownTimeout
}

func newHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	cfg.ApplyDefaults()
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

func BootS3Gateway() (*http.Server, config.Config, error) {
	cfg := config.LoadConfig()

	up, err := newUpstreamS3(context.Background(), cfg)
	if err != nil {
		return nil, cfg, fmt.Errorf("init upstream s3: %w", err)
	}

	s := newServer(cfg, up)

	adminHandler := adminWebpageHandler(s)

	httpSrv := newHTTPServer(cfg, s.withAuth(s, adminHandler))
	return httpSrv, cfg, nil
}
