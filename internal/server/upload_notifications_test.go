package server

import (
	"context"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

type recordingUploadNotifier struct {
	events []uploadnotify.Event
	err    error
}

func (n *recordingUploadNotifier) Notify(_ context.Context, event uploadnotify.Event) error {
	n.events = append(n.events, event)
	return n.err
}
