package main

import (
	"net/http"

	adminpage "github.com/define42/s3gateway/internal/adminpage"
)

// adminWebpageHandler is a test helper that creates an admin handler for *server.
// Used by existing root-package tests.
func adminWebpageHandler(s *server) http.Handler {
	if s == nil {
		return adminpage.NewHandler(nil, "", 100, func(upn, pass string) (map[string]struct{}, error) {
			return nil, nil
		})
	}
	return adminpage.NewHandler(s.up, s.cfg.CookieSecret, s.cfg.GroupCacheMaxEntries, s.groupsForCredentials)
}
