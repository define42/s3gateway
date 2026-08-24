// Package app composes and runs the s3gateway application.
package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/server"
	"github.com/define42/s3gateway/internal/upstream"
)

// Boot constructs the configured gateway HTTP server.
func Boot() (*http.Server, config.Config, error) {
	cfg := config.LoadConfig()

	up, err := upstream.New(context.Background(), cfg)
	if err != nil {
		return nil, cfg, fmt.Errorf("init upstream s3: %w", err)
	}

	gateway := server.New(cfg, up)
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
	return httpServer, cfg, nil
}
