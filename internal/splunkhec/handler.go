// Package splunkhec provides a buffered slog handler for Splunk HTTP Event
// Collector (HEC).
package splunkhec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	maxBatchBytes      = 1 << 20
	maxPendingBytes    = 64 << 20
	maxResponseBytes   = 64 << 10
	hecSource          = "s3gateway"
	hecSourceType      = "_json"
)

// Options configures a Handler. Endpoint must be the complete Splunk HEC JSON
// event URL, normally ending in /services/collector/event.
type Options struct {
	Endpoint      string
	Token         string
	Index         string
	FlushInterval time.Duration
	HTTPClient    *http.Client
	LocalHandler  slog.Handler
	ErrorWriter   io.Writer
}

type handlerOperation struct {
	attrs []slog.Attr
	group string
}

type handlerCore struct {
	endpoint      string
	token         string
	index         string
	flushInterval time.Duration
	httpClient    *http.Client
	diagnostic    *slog.Logger

	mu           sync.Mutex
	pending      [][]byte
	pendingBytes int
	dropped      uint64
	closed       bool

	flushMu sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// Handler writes each record to a local handler immediately and buffers a
// Splunk HEC copy until the configured flush interval elapses.
type Handler struct {
	core       *handlerCore
	local      slog.Handler
	operations []handlerOperation
}

type hecEvent struct {
	Time       float64         `json:"time"`
	Source     string          `json:"source"`
	SourceType string          `json:"sourcetype"`
	Index      string          `json:"index"`
	Event      json.RawMessage `json:"event"`
}

type hecResponse struct {
	Code *int `json:"code"`
}

// NewHandler validates the HEC endpoint and required options, then starts the
// periodic flush worker. A nil HTTPClient uses a client with a 10-second
// timeout; a nil ErrorWriter sends diagnostics to standard error.
func NewHandler(options Options) (*Handler, error) {
	endpoint := strings.TrimSpace(options.Endpoint)
	token := strings.TrimSpace(options.Token)
	index := strings.TrimSpace(options.Index)
	if err := validateOptions(endpoint, token, index, options.FlushInterval, options.LocalHandler); err != nil {
		return nil, err
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	errorWriter := options.ErrorWriter
	if errorWriter == nil {
		errorWriter = os.Stderr
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	core := &handlerCore{
		endpoint:      endpoint,
		token:         token,
		index:         index,
		flushInterval: options.FlushInterval,
		httpClient:    httpClient,
		diagnostic: slog.New(slog.NewJSONHandler(errorWriter, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		})),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	handler := &Handler{
		core:  core,
		local: options.LocalHandler,
	}
	go core.run(workerCtx)
	return handler, nil
}

func validateOptions(endpoint, token, index string, flushInterval time.Duration, local slog.Handler) error {
	if endpoint == "" {
		return errors.New("splunk HEC endpoint is required")
	}
	parsedEndpoint, err := url.ParseRequestURI(endpoint)
	if err != nil || parsedEndpoint.Host == "" {
		return errors.New("splunk HEC endpoint must be an absolute URL")
	}
	if !strings.EqualFold(parsedEndpoint.Scheme, "http") && !strings.EqualFold(parsedEndpoint.Scheme, "https") {
		return errors.New("splunk HEC endpoint must use http or https")
	}
	if parsedEndpoint.User != nil {
		return errors.New("splunk HEC endpoint must not contain user information")
	}
	if token == "" {
		return errors.New("splunk HEC token is required")
	}
	if index == "" {
		return errors.New("splunk HEC index is required")
	}
	if flushInterval <= 0 {
		return errors.New("splunk HEC flush interval must be greater than zero")
	}
	if local == nil {
		return errors.New("local slog handler is required")
	}
	return nil
}

// Enabled reports whether the local handler accepts the record. HEC receives
// the same records that are emitted locally.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.local.Enabled(ctx, level)
}

// Handle emits a record locally and queues its structured HEC envelope.
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	localErr := h.local.Handle(ctx, record)

	payload, err := h.encode(ctx, record)
	if err != nil {
		h.core.diagnostic.Warn("failed to encode log for Splunk HEC", "error", err)
		return errors.Join(localErr, err)
	}
	h.core.enqueue(payload)
	return localErr
}

// WithAttrs returns a handler with the supplied slog attributes.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	attrsCopy := append([]slog.Attr(nil), attrs...)
	operations := append([]handlerOperation(nil), h.operations...)
	operations = append(operations, handlerOperation{attrs: attrsCopy})
	return &Handler{
		core:       h.core,
		local:      h.local.WithAttrs(attrs),
		operations: operations,
	}
}

// WithGroup returns a handler with the supplied slog group.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	operations := append([]handlerOperation(nil), h.operations...)
	operations = append(operations, handlerOperation{group: name})
	return &Handler{
		core:       h.core,
		local:      h.local.WithGroup(name),
		operations: operations,
	}
}

// Flush sends all currently buffered records to Splunk HEC. Failed and unsent
// records are restored to the front of the buffer for the next attempt.
func (h *Handler) Flush(ctx context.Context) error {
	return h.core.flush(ctx)
}

// Close stops the periodic worker and attempts one final flush. It is safe to
// call Close more than once.
func (h *Handler) Close(ctx context.Context) error {
	h.core.closeOnce.Do(func() {
		h.core.mu.Lock()
		h.core.closed = true
		h.core.mu.Unlock()

		h.core.cancel()
		select {
		case <-h.core.done:
			h.core.closeErr = h.core.flush(ctx)
		case <-ctx.Done():
			h.core.closeErr = fmt.Errorf("stopping Splunk HEC log worker: %w", ctx.Err())
		}
	})
	return h.core.closeErr
}

func (h *Handler) encode(ctx context.Context, record slog.Record) ([]byte, error) {
	var eventBuffer bytes.Buffer
	var eventHandler slog.Handler = slog.NewJSONHandler(&eventBuffer, nil)
	for _, operation := range h.operations {
		if operation.group != "" {
			eventHandler = eventHandler.WithGroup(operation.group)
			continue
		}
		eventHandler = eventHandler.WithAttrs(operation.attrs)
	}
	if err := eventHandler.Handle(ctx, record); err != nil {
		return nil, fmt.Errorf("encoding structured log event: %w", err)
	}

	eventTime := record.Time
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	payload, err := json.Marshal(hecEvent{
		Time:       float64(eventTime.Unix()) + float64(eventTime.Nanosecond())/float64(time.Second),
		Source:     hecSource,
		SourceType: hecSourceType,
		Index:      h.core.index,
		Event:      bytes.TrimSpace(eventBuffer.Bytes()),
	})
	if err != nil {
		return nil, fmt.Errorf("encoding Splunk HEC event envelope: %w", err)
	}
	return payload, nil
}

func (h *handlerCore) run(ctx context.Context) {
	ticker := time.NewTicker(h.flushInterval)
	defer func() {
		ticker.Stop()
		close(h.done)
	}()

	for {
		select {
		case <-ticker.C:
			if err := h.flush(ctx); err != nil {
				h.diagnostic.Warn("failed to flush logs to Splunk HEC", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (h *handlerCore) enqueue(payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	if len(payload) > maxPendingBytes || h.pendingBytes+len(payload) > maxPendingBytes {
		h.dropped++
		return
	}
	h.pending = append(h.pending, payload)
	h.pendingBytes += len(payload)
}

func (h *handlerCore) flush(ctx context.Context) error {
	h.flushMu.Lock()
	defer h.flushMu.Unlock()

	pending, dropped := h.takePending()
	if dropped > 0 {
		h.diagnostic.Warn(
			"logs dropped because the Splunk HEC buffer is full",
			"count", dropped,
			"max_bytes", maxPendingBytes,
		)
	}
	for len(pending) > 0 {
		count := batchEventCount(pending)
		if err := h.send(ctx, pending[:count]); err != nil {
			h.restorePending(pending)
			return err
		}
		pending = pending[count:]
	}
	return nil
}

func (h *handlerCore) takePending() ([][]byte, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := h.pending
	h.pending = nil
	h.pendingBytes = 0
	dropped := h.dropped
	h.dropped = 0
	return pending, dropped
}

func (h *handlerCore) restorePending(events [][]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	current := h.pending
	restored := make([][]byte, 0, len(events)+len(current))
	restoredBytes := 0
	for _, event := range events {
		restored = append(restored, event)
		restoredBytes += len(event)
	}
	for _, event := range current {
		if restoredBytes+len(event) > maxPendingBytes {
			h.dropped++
			continue
		}
		restored = append(restored, event)
		restoredBytes += len(event)
	}
	h.pending = restored
	h.pendingBytes = restoredBytes
}

func batchEventCount(events [][]byte) int {
	size := 0
	for i, event := range events {
		eventSize := len(event) + 1
		if i > 0 && size+eventSize > maxBatchBytes {
			return i
		}
		size += eventSize
	}
	return len(events)
}

func (h *handlerCore) send(ctx context.Context, events [][]byte) error {
	var body bytes.Buffer
	for _, event := range events {
		body.Write(event)
		body.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, &body)
	if err != nil {
		return fmt.Errorf("building Splunk HEC request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+h.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending Splunk HEC request: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("reading Splunk HEC response: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing Splunk HEC response: %w", closeErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("splunk HEC returned HTTP status %s", resp.Status)
	}

	var result hecResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("decoding Splunk HEC response: %w", err)
	}
	if result.Code == nil {
		return errors.New("splunk HEC response is missing a result code")
	}
	if *result.Code != 0 {
		return fmt.Errorf("splunk HEC rejected the batch with code %d", *result.Code)
	}
	return nil
}
