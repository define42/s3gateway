package server

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3xml"
	"github.com/define42/s3gateway/internal/upstream"
)

// withTransferLimits bounds active handlers before authentication or upload
// buffering. Progress extends the idle budget, including while streaming large
// objects; an idle request also cancels any outstanding upstream operation.
func withTransferLimits(cfg config.Config, next http.Handler) http.Handler {
	if next == nil {
		next = http.DefaultServeMux
	}
	slots := make(chan struct{}, cfg.MaxConcurrentRequests)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		preserveXMLRequestTrailers(r)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		activity := &transferActivity{
			controller: http.NewResponseController(w),
			cancel:     cancel,
			idle:       cfg.TransferIdleTimeout,
			deadline:   time.Now().Add(cfg.TransferIdleTimeout),
		}
		activity.timer = time.AfterFunc(activity.idle, activity.expire)
		defer activity.finish(cfg)
		writer := &transferResponseWriter{ResponseWriter: w, activity: activity}

		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				// Do not wait for an overloaded client's unread request body
				// before sending the rejection.
				if r.ProtoMajor == 1 {
					w.Header().Set("Connection", "close")
				}
				w.Header().Set("Retry-After", "1")
				s3xml.WriteError(writer, http.StatusServiceUnavailable, "SlowDown", "Please reduce concurrent requests")
				return
			}
		}
		r = r.WithContext(upstream.WithResponseProgress(ctx, activity.progress))
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &transferRequestBody{ReadCloser: r.Body, activity: activity}
		}
		next.ServeHTTP(writer, r)
	})
}

type transferActivity struct {
	mu            sync.Mutex
	controller    *http.ResponseController
	cancel        context.CancelFunc
	timer         *time.Timer
	idle          time.Duration
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	finished      bool
	expired       bool
}

func (a *transferActivity) progress() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.finished && !a.expired {
		a.deadline = time.Now().Add(a.idle)
	}
}

func (a *transferActivity) expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished {
		return
	}
	if remaining := time.Until(a.deadline); remaining > 0 {
		a.timer.Reset(remaining)
		return
	}
	a.expired = true
	a.cancel()
	// Context cancellation alone cannot interrupt a blocked client body read
	// or response write. These deadlines also work on individual HTTP/2 streams.
	_ = a.controller.SetReadDeadline(time.Now())
	_ = a.controller.SetWriteDeadline(time.Now())
}

func (a *transferActivity) finish(cfg config.Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.finished = true
	a.timer.Stop()
	if a.expired {
		return
	}
	// net/http may still drain unread body bytes and flush buffered output
	// after the handler returns. Bound that work without extending configured
	// absolute deadlines or shorter deadlines installed by an inner handler.
	deadline := time.Now().Add(a.idle)
	if cfg.ReadTimeout == 0 {
		_ = a.controller.SetReadDeadline(earlierTransferDeadline(deadline, a.readDeadline))
	}
	if cfg.WriteTimeout == 0 {
		_ = a.controller.SetWriteDeadline(earlierTransferDeadline(deadline, a.writeDeadline))
	}
}

func earlierTransferDeadline(idleDeadline, explicitDeadline time.Time) time.Time {
	if !explicitDeadline.IsZero() && explicitDeadline.Before(idleDeadline) {
		return explicitDeadline
	}
	return idleDeadline
}

type transferRequestBody struct {
	io.ReadCloser
	activity *transferActivity
}

func (b *transferRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.activity.progress()
	}
	return n, err
}

type transferResponseWriter struct {
	http.ResponseWriter
	activity *transferActivity
}

func (w *transferResponseWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return w.ResponseWriter.Write(p)
	}
	var total int
	for len(p) > 0 {
		// Large writes must expose progress to the watchdog even when the
		// caller supplies an entire object in one call.
		chunk := p[:min(len(p), 32<<10)]
		n, err := w.ResponseWriter.Write(chunk)
		total += n
		if n > 0 {
			w.activity.progress()
		}
		if err != nil {
			return total, err
		}
		if n != len(chunk) {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

func (w *transferResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.activity.progress()
}

func (w *transferResponseWriter) FlushError() error {
	err := w.activity.controller.Flush()
	if err == nil {
		w.activity.progress()
	}
	return err
}

func (w *transferResponseWriter) Flush() { _ = w.FlushError() }

func (w *transferResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *transferResponseWriter) SetReadDeadline(deadline time.Time) error {
	w.activity.mu.Lock()
	defer w.activity.mu.Unlock()
	if w.activity.expired {
		return context.DeadlineExceeded
	}
	w.activity.readDeadline = deadline
	return w.activity.controller.SetReadDeadline(deadline)
}

func (w *transferResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.activity.mu.Lock()
	defer w.activity.mu.Unlock()
	if w.activity.expired {
		return context.DeadlineExceeded
	}
	w.activity.writeDeadline = deadline
	return w.activity.controller.SetWriteDeadline(deadline)
}
