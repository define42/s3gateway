package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

func (s *Server) notifyUpload(r *http.Request, event uploadnotify.Event) {
	if s.uploadNotifier == nil {
		return
	}

	event.SchemaVersion = uploadnotify.SchemaVersion
	event.OccurredAt = time.Now().UTC()

	ctx := context.Background()
	if r != nil {
		event.Uploader = UploaderFromRequest(r)
		ctx = context.WithoutCancel(r.Context())
	}
	if err := s.uploadNotifier.Notify(ctx, event); err != nil {
		slog.Warn(
			"failed to publish upload notification",
			"error", err,
			"event_name", event.EventName,
			"bucket", event.Bucket,
			"key", event.Key,
		)
	}
}
