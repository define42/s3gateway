package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/twmb/franz-go/pkg/kgo"
)

type fakePopConsumer struct {
	mu           sync.Mutex
	record       *kgo.Record
	consumeErr   error
	commitErr    error
	topic        string
	group        string
	groups       []string
	callCount    int
	acknowledged bool
	handleErr    error
}

func (c *fakePopConsumer) Consume(
	_ context.Context,
	topic string,
	group string,
	handle func(*kgo.Record) error,
) error {
	c.mu.Lock()
	c.topic = topic
	c.group = group
	c.groups = append(c.groups, group)
	c.callCount++
	record := c.record
	consumeErr := c.consumeErr
	commitErr := c.commitErr
	c.mu.Unlock()
	if consumeErr != nil {
		return consumeErr
	}
	if record == nil {
		return errors.New("fake pop consumer: missing record")
	}
	if err := handle(record); err != nil {
		c.mu.Lock()
		c.handleErr = err
		c.mu.Unlock()
		return fmt.Errorf("fake pop consumer: handle: %w", err)
	}
	if commitErr != nil {
		return fmt.Errorf("fake pop consumer: commit: %w", commitErr)
	}
	c.mu.Lock()
	c.acknowledged = true
	c.mu.Unlock()
	return nil
}

func popRecord(t *testing.T, topic string, event uploadnotify.Event) *kgo.Record {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal pop event: %v", err)
	}
	return &kgo.Record{Topic: topic, Value: payload}
}

func configurePopGateway(gateway *Server, consumer *fakePopConsumer) {
	gateway.cfg.EnableKafkaBucketTopic = true
	gateway.cfg.KafkaGlobalTopic = "_all"
	gateway.popConsumer = consumer
}

func allBucketsReadRules() []authz.Rule {
	return authz.RulesFromGroups(map[string]struct{}{
		authz.AllBucketsReadGroup: {},
	})
}

func TestHandlePopAPIBucketStreamsAndAcknowledgesObject(t *testing.T) {
	const body = "image body"
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/team2-images/path/object.jpg" {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("versionId"); got != "version-1" {
			t.Fatalf("upstream versionId = %q, want version-1", got)
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Content-Length", "10")
		w.Header().Set("ETag", `"etag-1"`)
		w.Header().Set("x-amz-version-id", "version-1")
		_, _ = w.Write([]byte(body))
	})
	defer cleanup()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			consumer := &fakePopConsumer{record: popRecord(t, "team2-images", uploadnotify.Event{
				EventID:   "019c0000-0000-7000-8000-000000000001",
				EventName: uploadnotify.EventObjectCreatedPut,
				Bucket:    "team2-images",
				Key:       "path/object.jpg",
				VersionID: "version-1",
			})}
			configurePopGateway(gateway, consumer)

			request := reqWithRulesAndUploader(
				httptest.NewRequest(method, "/api/pop/team2-images/scanner", nil),
				fullTeam2Rule(),
				"alice",
			)
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%q", response.Code, response.Body.String())
			}
			if response.Body.String() != body {
				t.Fatalf("body = %q, want %q", response.Body.String(), body)
			}
			if !response.Flushed {
				t.Fatal("response was not flushed before acknowledgement")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}
			if response.Header().Get("Content-Type") != "image/jpeg" {
				t.Fatalf("Content-Type = %q, want image/jpeg", response.Header().Get("Content-Type"))
			}
			if response.Header().Get("X-S3Gateway-Bucket") != "team2-images" {
				t.Fatalf("pop bucket header = %q", response.Header().Get("X-S3Gateway-Bucket"))
			}
			if response.Header().Get("X-S3Gateway-Object-Key") != "path%2Fobject.jpg" {
				t.Fatalf("pop key header = %q", response.Header().Get("X-S3Gateway-Object-Key"))
			}
			if response.Header().Get("X-S3Gateway-Event-ID") == "" {
				t.Fatal("missing event id header")
			}

			consumer.mu.Lock()
			defer consumer.mu.Unlock()
			if consumer.topic != "team2-images" || consumer.group != "alice:scanner" {
				t.Fatalf("consumer target = %q/%q, want team2-images/alice:scanner", consumer.topic, consumer.group)
			}
			if !consumer.acknowledged {
				t.Fatal("record was not acknowledged after successful response")
			}
		})
	}
}

func TestHandlePopAPIGlobalUsesEventBucket(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/team2-documents/report.pdf" {
			t.Fatalf("upstream path = %q, want /team2-documents/report.pdf", r.URL.Path)
		}
		_, _ = w.Write([]byte("pdf"))
	})
	defer cleanup()

	consumer := &fakePopConsumer{record: popRecord(t, "_all", uploadnotify.Event{
		EventName: uploadnotify.EventObjectCreatedPut,
		Bucket:    "team2-documents",
		Key:       "report.pdf",
	})}
	configurePopGateway(gateway, consumer)

	request := reqWithRulesAndUploader(
		httptest.NewRequest(http.MethodPost, "/api/pop/_all/archive", nil),
		allBucketsReadRules(),
		"alice",
	)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "pdf" {
		t.Fatalf("response = %d %q, want 200 pdf", response.Code, response.Body.String())
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.topic != "_all" || consumer.group != "alice:archive" || !consumer.acknowledged {
		t.Fatalf(
			"consumer state = topic %q group %q acknowledged %t",
			consumer.topic,
			consumer.group,
			consumer.acknowledged,
		)
	}
}

func TestHandlePopAPINamespacesConsumerGroupsByUsername(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called without an event")
	})
	defer cleanup()
	consumer := &fakePopConsumer{consumeErr: kafkapop.ErrNoEvent}
	configurePopGateway(gateway, consumer)

	for _, username := range []string{"alice", "bob"} {
		request := reqWithRulesAndUploader(
			httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil),
			fullTeam2Rule(),
			username,
		)
		response := httptest.NewRecorder()
		gateway.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf(
				"response for %q = %d %q, want empty 204",
				username,
				response.Code,
				response.Body.String(),
			)
		}
	}

	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	want := []string{"alice:scanner", "bob:scanner"}
	if len(consumer.groups) != len(want) {
		t.Fatalf("consumer groups = %v, want %v", consumer.groups, want)
	}
	for i := range want {
		if consumer.groups[i] != want[i] {
			t.Fatalf("consumer groups = %v, want %v", consumer.groups, want)
		}
	}
}

func TestHandlePopAPIDoesNotAcknowledgeWriteFailure(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("object"))
	})
	defer cleanup()

	consumer := &fakePopConsumer{record: popRecord(t, "team2-images", uploadnotify.Event{
		EventName: uploadnotify.EventObjectCreatedPut,
		Bucket:    "team2-images",
		Key:       "object.jpg",
	})}
	configurePopGateway(gateway, consumer)

	writeErr := errors.New("client disconnected")
	response := &failingPopResponseWriter{
		header:   make(http.Header),
		writeErr: writeErr,
	}
	request := reqWithRulesAndUploader(
		httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil),
		fullTeam2Rule(),
		"alice",
	)
	gateway.ServeHTTP(response, request)

	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.acknowledged {
		t.Fatal("record was acknowledged after response write failure")
	}
	if !errors.Is(consumer.handleErr, errPopResponseHandled) ||
		!strings.Contains(consumer.handleErr.Error(), writeErr.Error()) {
		t.Fatalf("handler error = %v, want wrapped write failure", consumer.handleErr)
	}
}

func TestHandlePopAPIDoesNotAcknowledgeShortObject(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	})
	defer cleanup()

	consumer := &fakePopConsumer{record: popRecord(t, "team2-images", uploadnotify.Event{
		EventName: uploadnotify.EventObjectCreatedPut,
		Bucket:    "team2-images",
		Key:       "object.jpg",
	})}
	configurePopGateway(gateway, consumer)

	request := reqWithRulesAndUploader(
		httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil),
		fullTeam2Rule(),
		"alice",
	)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)

	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.acknowledged {
		t.Fatal("record was acknowledged after a short object response")
	}
	if consumer.handleErr == nil ||
		!strings.Contains(consumer.handleErr.Error(), "unexpected EOF") {
		t.Fatalf("handler error = %v, want unexpected EOF", consumer.handleErr)
	}
}

type failingPopResponseWriter struct {
	header   http.Header
	status   int
	writeErr error
}

func (w *failingPopResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingPopResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *failingPopResponseWriter) Write([]byte) (int, error) {
	return 0, w.writeErr
}

func TestHandlePopAPINoEvent(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called without an event")
	})
	defer cleanup()
	consumer := &fakePopConsumer{consumeErr: kafkapop.ErrNoEvent}
	configurePopGateway(gateway, consumer)

	request := reqWithRulesAndUploader(
		httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil),
		fullTeam2Rule(),
		"alice",
	)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("response = %d %q, want empty 204", response.Code, response.Body.String())
	}
}

func TestHandlePopAPIValidation(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		path          string
		configure     func(*Server, *fakePopConsumer)
		rules         []authz.Rule
		wantStatus    int
		wantAllow     string
		wantCallCount int
		omitUsername  bool
	}{
		{
			name:       "incomplete route",
			method:     http.MethodPost,
			path:       "/api/pop/team2-images",
			configure:  configurePopGateway,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "method not allowed",
			method:     http.MethodPatch,
			path:       "/api/pop/team2-images/scanner",
			configure:  configurePopGateway,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusMethodNotAllowed,
			wantAllow:  popAllowedMethods,
		},
		{
			name:       "invalid group",
			method:     http.MethodPost,
			path:       "/api/pop/team2-images/bad!group",
			configure:  configurePopGateway,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "missing authenticated username",
			method:       http.MethodPost,
			path:         "/api/pop/team2-images/scanner",
			configure:    configurePopGateway,
			rules:        fullTeam2Rule(),
			wantStatus:   http.StatusUnauthorized,
			omitUsername: true,
		},
		{
			name:   "bucket topics disabled",
			method: http.MethodPost,
			path:   "/api/pop/team2-images/scanner",
			configure: func(gateway *Server, consumer *fakePopConsumer) {
				gateway.popConsumer = consumer
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:          "global read forbidden before consume",
			method:        http.MethodPost,
			path:          "/api/pop/_all/archive",
			configure:     configurePopGateway,
			rules:         fullTeam2Rule(),
			wantStatus:    http.StatusForbidden,
			wantCallCount: 0,
		},
		{
			name:   "global topic disabled",
			method: http.MethodPost,
			path:   "/api/pop/_all/archive",
			configure: func(gateway *Server, consumer *fakePopConsumer) {
				gateway.cfg.EnableKafkaBucketTopic = true
				gateway.popConsumer = consumer
			},
			rules:      allBucketsReadRules(),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "bucket read forbidden",
			method:     http.MethodPost,
			path:       "/api/pop/team2-images/scanner",
			configure:  configurePopGateway,
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "pop consumer unavailable",
			method: http.MethodPost,
			path:   "/api/pop/team2-images/scanner",
			configure: func(gateway *Server, _ *fakePopConsumer) {
				gateway.cfg.EnableKafkaBucketTopic = true
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
				t.Fatal("upstream must not be called for invalid request")
			})
			defer cleanup()
			consumer := &fakePopConsumer{}
			tt.configure(gateway, consumer)

			request := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.omitUsername {
				request = reqWithRules(request, tt.rules)
			} else {
				request = reqWithRulesAndUploader(request, tt.rules, "alice")
			}
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, tt.wantStatus, response.Body.String())
			}
			if got := response.Header().Get("Allow"); got != tt.wantAllow {
				t.Fatalf("Allow = %q, want %q", got, tt.wantAllow)
			}
			consumer.mu.Lock()
			callCount := consumer.callCount
			consumer.mu.Unlock()
			if callCount != tt.wantCallCount {
				t.Fatalf("consumer call count = %d, want %d", callCount, tt.wantCallCount)
			}
		})
	}
}

func TestHandlePopAPIRejectsUnusableEvents(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		topic      string
		value      []byte
		rules      []authz.Rule
		wantStatus int
	}{
		{
			name:       "malformed json",
			path:       "/api/pop/team2-images/scanner",
			topic:      "team2-images",
			value:      []byte("{"),
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadGateway,
		},
		{
			name:  "bucket mismatch",
			path:  "/api/pop/team2-images/scanner",
			topic: "team2-images",
			value: popRecord(t, "team2-images", uploadnotify.Event{
				Bucket: "team2-other",
				Key:    "object",
			}).Value,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
				t.Fatal("upstream must not be called for rejected event")
			})
			defer cleanup()
			consumer := &fakePopConsumer{record: &kgo.Record{Topic: tt.topic, Value: tt.value}}
			configurePopGateway(gateway, consumer)

			request := reqWithRulesAndUploader(
				httptest.NewRequest(http.MethodPost, tt.path, nil),
				tt.rules,
				"alice",
			)
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, tt.wantStatus, response.Body.String())
			}
			consumer.mu.Lock()
			acknowledged := consumer.acknowledged
			consumer.mu.Unlock()
			if acknowledged {
				t.Fatal("rejected event was acknowledged")
			}
		})
	}
}

func TestHandlePopAPICommitFailureOccursAfterBody(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("object"))
	})
	defer cleanup()
	consumer := &fakePopConsumer{
		record: popRecord(t, "team2-images", uploadnotify.Event{
			Bucket: "team2-images",
			Key:    "object",
		}),
		commitErr: errors.New("commit unavailable"),
	}
	configurePopGateway(gateway, consumer)

	request := reqWithRulesAndUploader(
		httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil),
		fullTeam2Rule(),
		"alice",
	)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "object" {
		t.Fatalf("response = %d %q, want 200 object", response.Code, response.Body.String())
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.acknowledged {
		t.Fatal("record was marked acknowledged after commit failure")
	}
	if consumer.handleErr != nil {
		t.Fatalf("body handler error = %v, want nil before commit failure", consumer.handleErr)
	}
}

func TestParsePopAPIPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantScope string
		wantGroup string
		wantOK    bool
	}{
		{name: "bucket", path: "/api/pop/images/scanner", wantScope: "images", wantGroup: "scanner", wantOK: true},
		{name: "global", path: "/api/pop/_all/archive/", wantScope: "_all", wantGroup: "archive", wantOK: true},
		{name: "missing group", path: "/api/pop/images", wantOK: false},
		{name: "extra segment", path: "/api/pop/images/scanner/extra", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, group, ok := parsePopAPIPath(tt.path)
			if scope != tt.wantScope || group != tt.wantGroup || ok != tt.wantOK {
				t.Fatalf(
					"parsePopAPIPath(%q) = %q, %q, %t; want %q, %q, %t",
					tt.path,
					scope,
					group,
					ok,
					tt.wantScope,
					tt.wantGroup,
					tt.wantOK,
				)
			}
		})
	}
}

func TestPopConsumerGroupID(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		requestedGroup string
		want           string
		wantOK         bool
	}{
		{
			name:           "simple",
			username:       "alice",
			requestedGroup: "scanner",
			want:           "alice:scanner",
			wantOK:         true,
		},
		{
			name:           "common punctuation",
			username:       "alice.smith",
			requestedGroup: "image_scanner-v2.prod",
			want:           "alice.smith:image_scanner-v2.prod",
			wantOK:         true,
		},
		{name: "missing username", requestedGroup: "scanner"},
		{name: "empty group", username: "alice"},
		{name: "path traversal", username: "alice", requestedGroup: ".."},
		{name: "invalid group punctuation", username: "alice", requestedGroup: "scanner!"},
		{name: "invalid username punctuation", username: "alice:admin", requestedGroup: "scanner"},
		{
			name:           "combined id too long",
			username:       "alice",
			requestedGroup: strings.Repeat("a", maxKafkaGroupIDBytes-len("alice:")+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := popConsumerGroupID(tt.username, tt.requestedGroup)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf(
					"popConsumerGroupID(%q, %q) = %q, %t; want %q, %t",
					tt.username,
					tt.requestedGroup,
					got,
					ok,
					tt.want,
					tt.wantOK,
				)
			}
		})
	}
}

var _ PopConsumer = (*fakePopConsumer)(nil)
var _ http.ResponseWriter = (*failingPopResponseWriter)(nil)
