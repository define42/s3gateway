// Package uploadnotify publishes successful S3 upload events.
package uploadnotify

import "time"

const SchemaVersion = 1

type EventName string

const (
	EventObjectCreatedPut                     EventName = "ObjectCreated:Put"
	EventObjectCreatedCompleteMultipartUpload EventName = "ObjectCreated:CompleteMultipartUpload"
)

// Event describes an object that the upstream S3 service has confirmed was
// created. UploadID is set only for completed multipart uploads.
type Event struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	EventName     EventName `json:"event_name"`
	Bucket        string    `json:"bucket"`
	Key           string    `json:"key"`
	ETag          string    `json:"etag,omitempty"`
	VersionID     string    `json:"version_id,omitempty"`
	UploadID      string    `json:"upload_id,omitempty"`
	Uploader      string    `json:"uploader,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
}
