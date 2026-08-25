package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/define42/s3gateway/internal/config"
)

func BenchmarkS3AuditMiddleware(b *testing.B) {
	request := httptest.NewRequest(http.MethodGet, "/bucket/object", nil)
	w := &auditBenchmarkResponseWriter{header: make(http.Header)}

	newHandler := func(level slog.Level) http.Handler {
		s := New(config.Config{S3AuditHashKey: testAuditHashKey}, nil)
		s.logger = slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: level}))
		return s.WithS3Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.setS3AuditPrincipal(r, "benchmark@example.com")
			markS3AuditAuthenticated(r)
			w.WriteHeader(http.StatusNoContent)
		}))
	}

	b.Run("disabled", func(b *testing.B) {
		handler := newHandler(slog.LevelWarn)
		b.ReportAllocs()
		for b.Loop() {
			handler.ServeHTTP(w, request)
		}
	})

	b.Run("enabled", func(b *testing.B) {
		handler := newHandler(slog.LevelInfo)
		b.ReportAllocs()
		for b.Loop() {
			handler.ServeHTTP(w, request)
		}
	})
}

type auditBenchmarkResponseWriter struct {
	header http.Header
}

func (w *auditBenchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (*auditBenchmarkResponseWriter) WriteHeader(int) {}

func (*auditBenchmarkResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
