package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func TestCleanupAllSharesDeadlineAndJoinsDependencies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var started, finished atomic.Int32
		functions := make([]contextCleanup, 3)
		for i := range functions {
			functions[i] = func(ctx context.Context) error {
				started.Add(1)
				<-ctx.Done()
				finished.Add(1)
				return ctx.Err()
			}
		}
		cleanup := cleanupAll(&functions)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- cleanup(ctx) }()
		synctest.Wait()
		if started.Load() != 3 {
			t.Fatalf("only %d dependency closes started", started.Load())
		}
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cleanup error = %v", err)
		}
		if finished.Load() != 3 {
			t.Fatalf("only %d dependency closes finished", finished.Load())
		}
		_ = cleanup(t.Context())
		if started.Load() != 3 {
			t.Fatal("repeated cleanup closed dependencies again")
		}
	})
}

func TestRunSharesHTTPShutdownDeadlineWithCleanup(t *testing.T) {
	restoreDefaultLogger(t)
	synctest.Test(t, func(t *testing.T) {
		signalCtx, sendSignal := context.WithCancel(t.Context())
		defer sendSignal()
		serverConn, clientConn := net.Pipe()
		defer func() { _ = serverConn.Close(); _ = clientConn.Close() }()
		listener := &shutdownTestListener{conn: serverConn, closed: make(chan struct{})}
		defer func() { _ = listener.Close() }()
		handling := make(chan struct{})
		release := make(chan struct{})
		httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Error(err)
				return
			}
			close(handling)
			<-release
			w.WriteHeader(http.StatusOK)
		})}
		var cleanupFinished atomic.Bool
		dependencies := baseRunDependencies(signalCtx)
		dependencies.loadConfig = func() config.Config { return config.Config{ShutdownTimeout: 10 * time.Second} }
		dependencies.boot = func(config.Config) (*http.Server, contextCleanup, error) {
			return httpServer, func(ctx context.Context) error {
				<-ctx.Done()
				cleanupFinished.Store(true)
				return ctx.Err()
			}, nil
		}
		dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) { return listener, false, nil }
		runDone := make(chan int, 1)
		go func() { runDone <- run(dependencies) }()
		uploadDone := shutdownTestUpload(clientConn)
		<-handling
		started := time.Now()
		sendSignal()
		synctest.Wait()
		time.Sleep(3 * time.Second)
		close(release)
		if err := <-uploadDone; err != nil {
			t.Fatal(err)
		}
		if code := <-runDone; code != 0 {
			t.Fatalf("run exit code = %d", code)
		}
		if elapsed := time.Since(started); elapsed != 10*time.Second {
			t.Fatalf("shutdown took %s, want one shared 10s budget", elapsed)
		}
		if !cleanupFinished.Load() {
			t.Fatal("run returned before cleanup finished")
		}
	})
}
