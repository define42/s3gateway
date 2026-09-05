// Package app composes and runs the s3gateway application.
package app

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/kafkatopic"
	"github.com/define42/s3gateway/internal/server"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/define42/s3gateway/internal/upstream"
)

// Boot loads process configuration and constructs the gateway HTTP server and
// optional Kafka integrations. Configuration failures terminate the process;
// component initialization failures are returned. The caller must invoke the
// returned cleanup function after HTTP requests have finished. Cleanup is safe
// to call more than once.
func Boot() (*http.Server, config.Config, func(), error) {
	cfg := config.LoadConfig()
	httpServer, cleanup, err := boot(cfg)
	return httpServer, cfg, cleanup, err
}

func boot(cfg config.Config) (*http.Server, func(), error) {
	cfg.ApplyDefaults()
	up, err := upstream.New(context.Background(), cfg)
	if err != nil {
		return nil, func() {}, fmt.Errorf("init upstream s3: %w", err)
	}

	var serverOptions []server.Option
	var adminOptions []adminpage.Option
	var cleanupFunctions []func()
	cleanup := sync.OnceFunc(func() {
		for _, cleanupFunction := range slices.Backward(cleanupFunctions) {
			cleanupFunction()
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
		adminOptions = append(adminOptions, adminpage.WithUploadNotifier(publisher))

		topicLister, err := kafkatopic.New(cfg.KafkaBrokers, cfg.KafkaNotificationTimeout)
		if err != nil {
			cleanup()
			return nil, cleanup, fmt.Errorf("init kafka topic lister: %w", err)
		}
		cleanupFunctions = append(cleanupFunctions, topicLister.Close)
		adminOptions = append(
			adminOptions,
			adminpage.WithKafkaTopicLister(topicLister, cfg.KafkaGlobalTopic),
		)

		popManager, err := kafkapop.New(kafkapop.Options{
			Brokers:      cfg.KafkaBrokers,
			Timeout:      cfg.KafkaPopTimeout,
			IdleTimeout:  cfg.KafkaPopIdleTimeout,
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
	adminHandler := adminpage.NewHandlerWithContext(
		up,
		cfg.CookieSecret,
		cfg.GroupCacheMaxEntries,
		cfg.RequiredUploadMetadataKeys,
		gateway.GroupsForCredentialsContext,
		adminOptions...,
	)
	httpServer := server.NewHTTPServer(
		cfg,
		gateway.WithS3Audit(gateway.WithAuth(gateway, adminHandler)),
	)
	return httpServer, cleanup, nil
}
