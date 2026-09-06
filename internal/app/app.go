// Package app composes and runs the s3gateway application.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	httpServer, closeContext, err := bootWithContextCleanup(cfg)
	return httpServer, func() {
		ctx, cancel := context.WithTimeout(context.Background(), server.EffectiveShutdownTimeout(cfg))
		defer cancel()
		_ = closeContext(ctx)
	}, err
}

type contextCleanup func(context.Context) error

// cleanupAll gives every dependency the same budget and waits for actual
// cleanup completion. Dependencies must interrupt their own I/O on cancellation.
func cleanupAll(functions *[]contextCleanup) contextCleanup {
	var once sync.Once
	var cleanupErr error
	return func(ctx context.Context) error {
		once.Do(func() {
			var pending sync.WaitGroup
			results := make(chan error, len(*functions))
			for _, cleanup := range *functions {
				pending.Go(func() { results <- cleanup(ctx) })
			}
			pending.Wait()
			close(results)
			for err := range results {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		})
		return cleanupErr
	}
}

func bootWithContextCleanup(cfg config.Config) (*http.Server, contextCleanup, error) {
	cfg.ApplyDefaults()
	up, err := upstream.New(context.Background(), cfg)
	if err != nil {
		return nil, func(context.Context) error { return nil }, fmt.Errorf("init upstream s3: %w", err)
	}

	var serverOptions []server.Option
	adminOptions := []adminpage.Option{adminpage.WithPublicOrigin(cfg.AdminPublicOrigin)}
	var cleanupFunctions []contextCleanup
	cleanup := cleanupAll(&cleanupFunctions)
	cleanupInitialization := func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = cleanup(ctx)
	}
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
		cleanupFunctions = append(cleanupFunctions, publisher.CloseContext)
		serverOptions = append(serverOptions, server.WithUploadNotifier(publisher))
		adminOptions = append(adminOptions, adminpage.WithUploadNotifier(publisher))

		topicLister, err := kafkatopic.New(cfg.KafkaBrokers, cfg.KafkaNotificationTimeout)
		if err != nil {
			cleanupInitialization()
			return nil, cleanup, fmt.Errorf("init kafka topic lister: %w", err)
		}
		cleanupFunctions = append(cleanupFunctions, topicLister.CloseContext)
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
			cleanupInitialization()
			return nil, cleanup, fmt.Errorf("init kafka pop consumer: %w", err)
		}
		cleanupFunctions = append(cleanupFunctions, popManager.CloseContext)
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
