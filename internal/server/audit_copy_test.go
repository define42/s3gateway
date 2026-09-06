package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func TestS3AuditResponseWriterCopyFallback(t *testing.T) {
	errRead := errors.New("upstream read failed")
	errWrite := errors.New("downstream write failed")
	payload := bytes.Repeat([]byte("x"), 3*(32<<10)+17)
	for _, tc := range []struct {
		name     string
		payload  []byte
		limit    int
		readErr  error
		writeErr error
		wantErr  error
		wantN    int64
	}{
		{
			name: "multiple buffers", payload: payload, limit: -1,
			wantN: int64(len(payload)),
		},
		{name: "empty body", limit: -1},
		{
			name: "upstream error after bytes", payload: payload, limit: -1,
			readErr: errRead, wantErr: errRead, wantN: int64(len(payload)),
		},
		{
			name: "downstream short write", payload: payload, limit: 7,
			wantErr: io.ErrShortWrite, wantN: 7,
		},
		{
			name: "downstream error after bytes", payload: payload, limit: 7,
			writeErr: errWrite, wantErr: errWrite, wantN: 7,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			underlying := &auditPartialWriter{
				ResponseRecorder: httptest.NewRecorder(),
				limit:            tc.limit,
				err:              tc.writeErr,
			}
			audit := &s3AuditResponseWriter{ResponseWriter: underlying}
			var reader io.Reader = bytes.NewReader(tc.payload)
			if tc.readErr != nil {
				reader = io.MultiReader(reader, iotest.ErrReader(tc.readErr))
			}
			// Hide source WriterTo so io.Copy invokes the audit ReaderFrom fallback.
			n, err := io.Copy(audit, struct{ io.Reader }{Reader: reader})
			if n != tc.wantN || audit.BytesWritten() != tc.wantN || !errors.Is(err, tc.wantErr) {
				t.Fatalf("copied=%d audited=%d err=%v, want bytes=%d err=%v",
					n, audit.BytesWritten(), err, tc.wantN, tc.wantErr)
			}
			if !bytes.Equal(underlying.Body.Bytes(), tc.payload[:tc.wantN]) {
				t.Fatal("copied body differs from successfully written source bytes")
			}
			if audit.Status() != http.StatusOK || underlying.Code != http.StatusOK {
				t.Fatalf("implicit status differs: audit=%d underlying=%d", audit.Status(), underlying.Code)
			}
		})
	}
}

func TestS3AuditResponseWriterCopyPreservesTransferProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = time.Second
		payload := bytes.Repeat([]byte("x"), 3*(32<<10))
		underlying := &transferSlowWriter{ResponseRecorder: httptest.NewRecorder(), delay: idle / 2}
		srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			audit := &s3AuditResponseWriter{ResponseWriter: w}
			n, err := io.Copy(audit, struct{ io.Reader }{Reader: bytes.NewReader(payload)})
			if err != nil || n != int64(len(payload)) || audit.BytesWritten() != n {
				t.Fatalf("copied=%d audited=%d err=%v", n, audit.BytesWritten(), err)
			}
			if r.Context().Err() != nil {
				t.Fatalf("healthy progressing audited copy canceled: %v", r.Context().Err())
			}
		}))
		started := time.Now()
		srv.Handler.ServeHTTP(underlying, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
		if time.Since(started) <= idle || !bytes.Equal(underlying.Body.Bytes(), payload) {
			t.Fatal("test did not preserve the full copy across multiple idle periods")
		}
	})
}

func TestS3AuditResponseWriterCopyPreservesIdleCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = time.Second
		payload := []byte("partial object")
		underlying := &transferDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			audit := &s3AuditResponseWriter{ResponseWriter: w}
			reader := io.MultiReader(bytes.NewReader(payload), auditCanceledReader{ctx: r.Context()})
			n, err := io.Copy(audit, struct{ io.Reader }{Reader: reader})
			if !errors.Is(err, context.Canceled) || n != int64(len(payload)) || audit.BytesWritten() != n {
				t.Fatalf("idle cancellation: copied=%d audited=%d err=%v", n, audit.BytesWritten(), err)
			}
		}))
		srv.Handler.ServeHTTP(underlying, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
		if underlying.readDeadline.IsZero() || underlying.writeDeadline.IsZero() {
			t.Fatal("idle cancellation failed to set transfer deadlines")
		}
	})
}

type auditPartialWriter struct {
	*httptest.ResponseRecorder
	limit int
	err   error
}

func (w *auditPartialWriter) Write(p []byte) (int, error) {
	if w.limit >= 0 {
		p = p[:min(w.limit, len(p))]
	}
	n, _ := w.ResponseRecorder.Write(p)
	return n, w.err
}

type auditCanceledReader struct {
	ctx context.Context
}

func (r auditCanceledReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}
