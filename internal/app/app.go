// Package app composes and runs the s3gateway application.
package app

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/server"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/define42/s3gateway/internal/upstream"
)

// Boot loads process configuration and constructs the gateway HTTP server and
// optional Kafka integrations. Configuration failures terminate the process;
// component initialization failures are returned.
func Boot() (*http.Server, config.Config, error) {
	cfg := config.LoadConfig()
	httpServer, _, err := boot(cfg)
	return httpServer, cfg, err
}

func boot(cfg config.Config) (*http.Server, func(), error) {
	cfg.ApplyDefaults()
	up, err := upstream.New(context.Background(), cfg)
	if err != nil {
		return nil, func() {}, fmt.Errorf("init upstream s3: %w", err)
	}

	var serverOptions []server.Option
	var cleanupFunctions []func()
	cleanup := sync.OnceFunc(func() {
		for i := len(cleanupFunctions) - 1; i >= 0; i-- {
			cleanupFunctions[i]()
		}
	})
	if len(cfg.KafkaBrokers) > 0 {
		publisher, err := uploadnotify.NewKafkaPublisher(
			cfg.KafkaBrokers,
			cfg.EnableKafkaBucketTopic,
			cfg.KafkaGlobalTopic,
			cfg.KafkaNotificationTimeout,
		)
		if err != nil {
			return nil, cleanup, fmt.Errorf("init kafka upload notifier: %w", err)
		}
		cleanupFunctions = append(cleanupFunctions, publisher.Close)
		serverOptions = append(serverOptions, server.WithUploadNotifier(publisher))

		popManager, err := kafkapop.New(kafkapop.Options{
			Brokers:      cfg.KafkaBrokers,
			Timeout:      cfg.KafkaPopTimeout,
			MaxConsumers: cfg.KafkaPopMaxConsumers,
		})
		if err != nil {
			cleanup()
			return nil, cleanup, fmt.Errorf("init kafka pop consumer: %w", err)
		}
		cleanupFunctions = append(cleanupFunctions, popManager.Close)
		serverOptions = append(serverOptions, server.WithPopConsumer(popManager))
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
		gateway.WithS3Audit(gateway.WithAuth(gateway, adminHandler)),
	)
	httpServer.RegisterOnShutdown(cleanup)
	return httpServer, cleanup, nil
}
