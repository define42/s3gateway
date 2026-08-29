package splunkhec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type capturedRequest struct {
	method      string
	authorize   string
	contentType string
	body        []byte
}

func TestNewHandlerValidation(t *testing.T) {
	valid := Options{
		Endpoint:      "https://splunk.example:8088/services/collector/event",
		Token:         "token",
		Index:         "gateway",
		FlushInterval: time.Second,
		LocalHandler:  slog.NewJSONHandler(io.Discard, nil),
	}
	tests := []struct {
		name    string
		mutate  func(*Options)
		wantErr string
	}{
		{
			name: "missing endpoint",
			mutate: func(options *Options) {
				options.Endpoint = ""
			},
			wantErr: "endpoint is required",
		},
		{
			name: "relative endpoint",
			mutate: func(options *Options) {
				options.Endpoint = "/services/collector/event"
			},
			wantErr: "absolute URL",
		},
		{
			name: "unsupported endpoint scheme",
			mutate: func(options *Options) {
				options.Endpoint = "ftp://splunk.example/services/collector/event"
			},
			wantErr: "http or https",
		},
		{
			name: "endpoint user information",
			mutate: func(options *Options) {
				options.Endpoint = "https://user@splunk.example/services/collector/event"
			},
			wantErr: "user information",
		},
		{
			name: "missing token",
			mutate: func(options *Options) {
				options.Token = ""
			},
			wantErr: "token is required",
		},
		{
			name: "missing index",
			mutate: func(options *Options) {
				options.Index = ""
			},
			wantErr: "index is required",
		},
		{
			name: "invalid flush interval",
			mutate: func(options *Options) {
				options.FlushInterval = 0
			},
			wantErr: "greater than zero",
		},
		{
			name: "missing local handler",
			mutate: func(options *Options) {
				options.LocalHandler = nil
			},
			wantErr: "local slog handler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := valid
			tt.mutate(&options)
			handler, err := NewHandler(options)
			if err == nil {
				closeHandler(t, handler)
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validation error mismatch: got=%q want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestHandlerFlushesStructuredBatch(t *testing.T) {
	requests := make(chan capturedRequest, 2)
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{
			method:      r.Method,
			authorize:   r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        body,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	var local bytes.Buffer
	handler := newTestHandler(t, hecServer.URL, time.Hour, &local)
	defer closeHandler(t, handler)
	logger := slog.New(handler)
	logger.With("component", "test").WithGroup("request").Info("first event", "request_id", "req-1")
	logger.Warn("second event", "attempt", 2)

	if got := bytes.Count(local.Bytes(), []byte{'\n'}); got != 2 {
		t.Fatalf("local log line count mismatch before HEC flush: got=%d want=2", got)
	}
	if err := handler.Flush(t.Context()); err != nil {
		t.Fatalf("flush logs: %v", err)
	}

	request := <-requests
	if request.method != http.MethodPost {
		t.Fatalf("HEC method mismatch: got=%q want=%q", request.method, http.MethodPost)
	}
	if request.authorize != "Splunk test-token" {
		t.Fatalf("HEC authorization mismatch: got=%q", request.authorize)
	}
	if request.contentType != "application/json; charset=utf-8" {
		t.Fatalf("HEC content type mismatch: got=%q", request.contentType)
	}

	events := decodeBatch(t, request.body)
	if len(events) != 2 {
		t.Fatalf("HEC event count mismatch: got=%d want=2", len(events))
	}
	for _, event := range events {
		if event.Index != "gateway" || event.Source != hecSource || event.SourceType != hecSourceType {
			t.Fatalf("HEC metadata mismatch: %+v", event)
		}
	}

	var first map[string]any
	if err := json.Unmarshal(events[0].Event, &first); err != nil {
		t.Fatalf("decode first structured event: %v", err)
	}
	if first["msg"] != "first event" || first["component"] != "test" {
		t.Fatalf("first structured event mismatch: %+v", first)
	}
	requestGroup, ok := first["request"].(map[string]any)
	if !ok || requestGroup["request_id"] != "req-1" {
		t.Fatalf("grouped request attributes mismatch: %+v", first["request"])
	}
}

func TestHandlerFlushesOnInterval(t *testing.T) {
	requests := make(chan capturedRequest, 2)
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{body: body}
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	handler := newTestHandler(t, hecServer.URL, 10*time.Millisecond, io.Discard)
	defer closeHandler(t, handler)
	slog.New(handler).Info("automatic flush")

	select {
	case request := <-requests:
		if events := decodeBatch(t, request.body); len(events) != 1 {
			t.Fatalf("automatic HEC event count mismatch: got=%d want=1", len(events))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for automatic HEC flush")
	}
}

func TestHandlerRetriesFailedBatch(t *testing.T) {
	requests := make(chan capturedRequest, 2)
	var attempts atomic.Int32
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{body: body}
		if attempts.Add(1) == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	handler := newTestHandler(t, hecServer.URL, time.Hour, io.Discard)
	defer closeHandler(t, handler)
	slog.New(handler).Info("retry this event")

	if err := handler.Flush(t.Context()); err == nil {
		t.Fatal("expected first HEC flush to fail")
	}
	if err := handler.Flush(t.Context()); err != nil {
		t.Fatalf("retry HEC flush: %v", err)
	}
	first := <-requests
	second := <-requests
	if !bytes.Equal(first.body, second.body) {
		t.Fatalf("retried HEC batch changed: first=%q second=%q", first.body, second.body)
	}
}

func TestHandlerCloseFlushesOnce(t *testing.T) {
	requests := make(chan capturedRequest, 2)
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{body: body}
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	var local bytes.Buffer
	handler := newTestHandler(t, hecServer.URL, time.Hour, &local)
	logger := slog.New(handler)
	logger.Info("before close")
	closeHandler(t, handler)
	closeHandler(t, handler)
	logger.Info("after close")

	select {
	case request := <-requests:
		if events := decodeBatch(t, request.body); len(events) != 1 {
			t.Fatalf("close HEC event count mismatch: got=%d want=1", len(events))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for close HEC flush")
	}
	select {
	case request := <-requests:
		t.Fatalf("unexpected second HEC request after close: %q", request.body)
	case <-time.After(20 * time.Millisecond):
	}
	if got := bytes.Count(local.Bytes(), []byte{'\n'}); got != 2 {
		t.Fatalf("local log line count mismatch after close: got=%d want=2", got)
	}
}

func TestBatchEventCount(t *testing.T) {
	tests := []struct {
		name   string
		sizes  []int
		wanted int
	}{
		{
			name:   "all events fit",
			sizes:  []int{100, 200, 300},
			wanted: 3,
		},
		{
			name:   "split before limit",
			sizes:  []int{maxBatchBytes / 2, maxBatchBytes / 2, 100},
			wanted: 1,
		},
		{
			name:   "oversized event sent alone",
			sizes:  []int{maxBatchBytes + 1, 100},
			wanted: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make([][]byte, len(tt.sizes))
			for i, size := range tt.sizes {
				events[i] = make([]byte, size)
			}
			if got := batchEventCount(events); got != tt.wanted {
				t.Fatalf("batch event count mismatch: got=%d want=%d", got, tt.wanted)
			}
		})
	}
}

func newTestHandler(t *testing.T, endpoint string, interval time.Duration, local io.Writer) *Handler {
	t.Helper()
	handler, err := NewHandler(Options{
		Endpoint:      endpoint,
		Token:         "test-token",
		Index:         "gateway",
		FlushInterval: interval,
		LocalHandler:  slog.NewJSONHandler(local, nil),
		ErrorWriter:   io.Discard,
	})
	if err != nil {
		t.Fatalf("create HEC handler: %v", err)
	}
	return handler
}

func closeHandler(t *testing.T, handler *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := handler.Close(ctx); err != nil {
		t.Fatalf("close HEC handler: %v", err)
	}
}

func decodeBatch(t *testing.T, body []byte) []hecEvent {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	var events []hecEvent
	for {
		var event hecEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode HEC batch: %v; body=%q", err, body)
		}
		events = append(events, event)
	}
	return events
}
