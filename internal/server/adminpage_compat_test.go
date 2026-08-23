package server

import (
	"net/http"

	adminpage "github.com/define42/s3gateway/internal/adminpage"
)

// adminWebpageHandler is a test helper that creates an admin handler for *Server.
// Used by existing root-package tests.
func adminWebpageHandler(s *Server) http.Handler {
	if s == nil {
		return adminpage.NewHandler(nil, "", 100, nil, func(upn, pass string) (map[string]struct{}, error) {
			return nil, nil
		})
	}
	return adminpage.NewHandler(s.up, s.cfg.CookieSecret, s.cfg.GroupCacheMaxEntries, s.cfg.RequiredUploadMetadataKeys, s.GroupsForCredentials)
}
