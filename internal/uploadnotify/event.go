// Package uploadnotify publishes successful S3 object-creation events.
package uploadnotify

import "time"

// SchemaVersion is the current JSON event schema version.
const SchemaVersion = 1

// EventName identifies the S3 object-creation operation that produced an event.
type EventName string

const (
	// EventObjectCreatedPut identifies a successful single-request object upload.
	EventObjectCreatedPut EventName = "ObjectCreated:Put"
	// EventObjectCreatedCopy identifies a successful server-side object copy.
	EventObjectCreatedCopy EventName = "ObjectCreated:Copy"
	// EventObjectCreatedCompleteMultipartUpload identifies a successfully
	// completed multipart upload.
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
