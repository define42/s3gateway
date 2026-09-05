package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/s3http"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	popAPIPathPrefix     = "/api/pop/"
	popGlobalScope       = "_all"
	popAllowedMethods    = "GET, POST"
	maxKafkaGroupIDBytes = 249
)

var errPopResponseHandled = errors.New("pop response handled")

// PopConsumer delivers one Kafka record to handle and commits it only when
// handle succeeds.
type PopConsumer interface {
	// Consume delivers at most one record for a topic and consumer group. The
	// implementation commits the record only after handle succeeds.
	Consume(
		context.Context,
		string,
		string,
		func(*kgo.Record) error,
	) error
}

func isPopAPIPath(path string) bool {
	return path == "/api/pop" || path == "/api/pop/" ||
		strings.HasPrefix(path, popAPIPathPrefix)
}

func isPopAPIMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodPost
}

func parsePopAPIPath(path string) (scope string, group string, ok bool) {
	if !strings.HasPrefix(path, popAPIPathPrefix) {
		return "", "", false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(path, popAPIPathPrefix), "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func validKafkaGroupIDComponent(value string) bool {
	if len(value) == 0 || len(value) > maxKafkaGroupIDBytes ||
		value == "." || value == ".." {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func popConsumerGroupID(username, requestedGroup string) (string, bool) {
	username = strings.TrimSpace(username)
	if !validKafkaGroupIDComponent(username) ||
		!validKafkaGroupIDComponent(requestedGroup) {
		return "", false
	}

	group := username + ":" + requestedGroup
	if len(group) > maxKafkaGroupIDBytes {
		return "", false
	}
	return group, true
}

func (s *Server) handlePopAPI(w http.ResponseWriter, r *http.Request) {
	scope, requestedGroup, ok := parsePopAPIPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !isPopAPIMethod(r.Method) {
		w.Header().Set("Allow", popAllowedMethods)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	username := UploaderFromRequest(r)
	if username == "" {
		writePopBasicAuthChallenge(w)
		return
	}
	group, ok := popConsumerGroupID(username, requestedGroup)
	if !ok {
		http.Error(w, "invalid kafka consumer group", http.StatusBadRequest)
		return
	}
	if s.popConsumer == nil || s.up == nil {
		http.Error(w, "pop service is unavailable", http.StatusServiceUnavailable)
		return
	}

	rules := authz.RulesFromRequest(r)
	topic := scope
	if scope == popGlobalScope {
		if !authz.CanReadAll(rules) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		topic = strings.TrimSpace(s.cfg.KafkaGlobalTopic)
		if topic == "" {
			http.Error(w, "global pop topic is disabled", http.StatusServiceUnavailable)
			return
		}
	} else {
		if !s.cfg.EnableKafkaBucketTopic {
			http.Error(w, "bucket pop topics are disabled", http.StatusServiceUnavailable)
			return
		}
		if !authz.CanRead(rules, scope) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	responseStarted := false
	err := s.popConsumer.Consume(
		r.Context(),
		topic,
		group,
		func(record *kgo.Record) error {
			if record.Topic != topic {
				responseStarted = true
				http.Error(w, "invalid kafka upload event", http.StatusBadGateway)
				return fmt.Errorf(
					"%w: record topic %q does not match %q",
					errPopResponseHandled,
					record.Topic,
					topic,
				)
			}

			var event uploadnotify.Event
			if err := json.Unmarshal(record.Value, &event); err != nil {
				responseStarted = true
				http.Error(w, "invalid kafka upload event", http.StatusBadGateway)
				return fmt.Errorf(
					"%w: decode kafka upload event: %v",
					errPopResponseHandled,
					err,
				)
			}
			event.Bucket = strings.TrimSpace(event.Bucket)
			if event.Bucket == "" || event.Key == "" {
				responseStarted = true
				http.Error(w, "invalid kafka upload event", http.StatusBadGateway)
				return fmt.Errorf(
					"%w: kafka upload event is missing bucket or key",
					errPopResponseHandled,
				)
			}
			if scope != popGlobalScope && event.Bucket != scope {
				responseStarted = true
				http.Error(w, "kafka event bucket does not match route", http.StatusBadGateway)
				return fmt.Errorf(
					"%w: event bucket %q does not match scope %q",
					errPopResponseHandled,
					event.Bucket,
					scope,
				)
			}
			if !authz.CanRead(rules, event.Bucket) {
				responseStarted = true
				http.Error(w, "Forbidden", http.StatusForbidden)
				return fmt.Errorf(
					"%w: read access denied for event bucket %q",
					errPopResponseHandled,
					event.Bucket,
				)
			}

			responseStarted = true
			if err := s.streamPoppedObject(w, r, event); err != nil {
				return fmt.Errorf("%w: %v", errPopResponseHandled, err)
			}
			return nil
		},
	)
	if err == nil {
		return
	}
	if errors.Is(err, kafkapop.ErrNoEvent) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if errors.Is(err, context.Canceled) && !responseStarted {
		return
	}
	if errors.Is(err, kafkapop.ErrConsumerLimit) && !responseStarted {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "pop consumer capacity reached", http.StatusServiceUnavailable)
		return
	}
	if errors.Is(err, errPopResponseHandled) || responseStarted {
		s.auditLogger().WarnContext(
			context.WithoutCancel(r.Context()),
			"Kafka pop event was not acknowledged",
			"topic", topic,
			"group", group,
			"error", err,
		)
		return
	}

	s.auditLogger().ErrorContext(
		context.WithoutCancel(r.Context()),
		"Kafka pop failed",
		"topic", topic,
		"group", group,
		"error", err,
	)
	http.Error(w, "could not pop kafka event", http.StatusBadGateway)
}

func (s *Server) streamPoppedObject(
	w http.ResponseWriter,
	r *http.Request,
	event uploadnotify.Event,
) error {
	input := &s3.GetObjectInput{
		Bucket: aws.String(event.Bucket),
		Key:    aws.String(event.Key),
	}
	if event.VersionID != "" {
		input.VersionId = aws.String(event.VersionID)
	}
	out, err := s.up.GetObject(r.Context(), input)
	if err != nil {
		s3http.WriteUpstreamError(w, err)
		return fmt.Errorf("get popped object: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Object metadata is untrusted; pop shares an origin with the admin UI.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("X-S3Gateway-Bucket", event.Bucket)
	w.Header().Set("X-S3Gateway-Object-Key", url.QueryEscape(event.Key))
	setSafePopHeader(w.Header(), "X-S3Gateway-Event-ID", event.EventID)
	setSafePopHeader(w.Header(), "X-S3Gateway-Event-Name", string(event.EventName))
	if out.ContentLength != nil && *out.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}

	w.WriteHeader(http.StatusOK)
	written, err := io.Copy(w, out.Body)
	if err != nil {
		return fmt.Errorf("write popped object: %w", err)
	}
	if out.ContentLength != nil && *out.ContentLength >= 0 &&
		written != *out.ContentLength {
		return fmt.Errorf(
			"write popped object: %w: wrote %d of %d bytes",
			io.ErrUnexpectedEOF,
			written,
			*out.ContentLength,
		)
	}
	if err := http.NewResponseController(w).Flush(); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		return fmt.Errorf("flush popped object: %w", err)
	}
	return nil
}

func setSafePopHeader(header http.Header, key, value string) {
	if value == "" || len(value) > 4096 {
		return
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return
		}
	}
	header.Set(key, value)
}
