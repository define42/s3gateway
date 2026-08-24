// Package app composes and runs the s3gateway application.
package app

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/server"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/define42/s3gateway/internal/upstream"
)

// Boot constructs the configured gateway HTTP server.
func Boot() (*http.Server, config.Config, error) {
	cfg := config.LoadConfig()
	httpServer, _, err := boot(cfg)
	return httpServer, cfg, err
}

func boot(cfg config.Config) (*http.Server, func(), error) {
	up, err := upstream.New(context.Background(), cfg)
	if err != nil {
		return nil, func() {}, fmt.Errorf("init upstream s3: %w", err)
	}

	var serverOptions []server.Option
	cleanup := func() {}
	if len(cfg.KafkaBrokers) > 0 {
		publisher, err := uploadnotify.NewKafkaPublisher(
			cfg.KafkaBrokers,
			cfg.KafkaTopic,
			cfg.KafkaNotificationTimeout,
		)
		if err != nil {
			return nil, cleanup, fmt.Errorf("init kafka upload notifier: %w", err)
		}
		cleanup = sync.OnceFunc(publisher.Close)
		serverOptions = append(serverOptions, server.WithUploadNotifier(publisher))
	}

	gateway := server.New(cfg, up, serverOptions...)
	adminHandler := adminpage.NewHandler(
		up,
		cfg.CookieSecret,
		cfg.GroupCacheMaxEntries,
		cfg.RequiredUploadMetadataKeys,
		gateway.GroupsForCredentials,
	)
	httpServer := server.NewHTTPServer(
		cfg,
		gateway.WithAuth(gateway, adminHandler),
	)
	httpServer.RegisterOnShutdown(cleanup)
	return httpServer, cleanup, nil
}
