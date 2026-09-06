package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

type shutdownTestConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *shutdownTestConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type shutdownTestListener struct {
	conn      net.Conn
	accepted  bool
	fail      <-chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (l *shutdownTestListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	select {
	case <-l.fail:
		return nil, errors.New("accept failed during upload")
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *shutdownTestListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *shutdownTestListener) Addr() net.Addr {
	return staticAddr("shutdown-test")
}

func shutdownTestUpload(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPut, "http://gateway/upload", strings.NewReader("uploaded object"))
		if err != nil {
			done <- err
			return
		}
		req.Close = true
		if err := req.Write(conn); err != nil {
			done <- err
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			done <- err
			return
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			done <- fmt.Errorf("upload status = %d, want %d", resp.StatusCode, http.StatusOK)
			return
		}
		done <- errors.Join(readErr, closeErr)
	}()
	return done
}

func TestRunDrainsUploadNotificationsBeforeCleanup(t *testing.T) {
	for _, tt := range []struct {
		name         string
		failListener bool
		wantExitCode int
	}{
		{name: "shutdown signal"},
		{name: "listener failure", failListener: true, wantExitCode: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			restoreDefaultLogger(t)
			synctest.Test(t, func(t *testing.T) {
				signalCtx, sendSignal := context.WithCancel(t.Context())
				defer sendSignal()
				serverConn, clientConn := net.Pipe()
				defer func() { _ = serverConn.Close() }()
				defer func() { _ = clientConn.Close() }()
				failAccept := make(chan struct{})
				listener := &shutdownTestListener{
					conn:   serverConn,
					fail:   failAccept,
					closed: make(chan struct{}),
				}
				defer func() { _ = listener.Close() }()

				notificationStarted := make(chan struct{})
				releaseNotification := make(chan struct{})
				finishNotification := sync.OnceFunc(func() { close(releaseNotification) })
				defer finishNotification()
				shutdownStarted := make(chan struct{})
				var notifications, cleanupCalls atomic.Int32
				var prematureCleanup atomic.Bool
				httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Errorf("read upload: %v", err)
						return
					}
					close(notificationStarted)
					<-releaseNotification
					notifications.Add(1)
					w.WriteHeader(http.StatusOK)
				})}
				httpServer.RegisterOnShutdown(sync.OnceFunc(func() { close(shutdownStarted) }))
				dependencies := baseRunDependencies(signalCtx)
				dependencies.boot = func(config.Config) (*http.Server, contextCleanup, error) {
					return httpServer, func(context.Context) error {
						if notifications.Load() != 1 {
							prematureCleanup.Store(true)
						}
						cleanupCalls.Add(1)
						return nil
					}, nil
				}
				dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
					return listener, false, nil
				}
				runDone := make(chan int, 1)
				go func() { runDone <- run(dependencies) }()
				uploadDone := shutdownTestUpload(clientConn)
				<-notificationStarted
				if tt.failListener {
					close(failAccept)
				} else {
					sendSignal()
				}
				synctest.Wait()
				if got := cleanupCalls.Load(); got != 0 {
					t.Fatalf("cleanup ran %d times while upload notification was pending", got)
				}
				select {
				case <-shutdownStarted:
				default:
					t.Fatal("HTTP shutdown did not start")
				}
				finishNotification()
				if err := <-uploadDone; err != nil {
					t.Fatalf("upload response: %v", err)
				}
				if exitCode := <-runDone; exitCode != tt.wantExitCode {
					t.Fatalf("run() exit code = %d, want %d", exitCode, tt.wantExitCode)
				}
				if prematureCleanup.Load() {
					t.Error("cleanup ran before upload notification completed")
				}
				if got := cleanupCalls.Load(); got != 1 {
					t.Fatalf("cleanup calls = %d, want 1", got)
				}
			})
		})
	}
}

func TestRunClosesActiveConnectionsBeforeCleanupOnShutdownTimeout(t *testing.T) {
	restoreDefaultLogger(t)
	synctest.Test(t, func(t *testing.T) {
		const shutdownTimeout = time.Second
		signalCtx, sendSignal := context.WithCancel(t.Context())
		defer sendSignal()
		serverSide, clientConn := net.Pipe()
		serverConn := &shutdownTestConn{Conn: serverSide}
		defer func() { _ = serverConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		listener := &shutdownTestListener{conn: serverConn, closed: make(chan struct{})}
		defer func() { _ = listener.Close() }()
		uploadStarted := make(chan struct{})
		requestCanceled := make(chan struct{})
		var cleanupCalls atomic.Int32
		var prematureCleanup atomic.Bool
		httpServer := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Errorf("read upload: %v", err)
				return
			}
			close(uploadStarted)
			<-r.Context().Done()
			close(requestCanceled)
		})}
		dependencies := baseRunDependencies(signalCtx)
		dependencies.loadConfig = func() config.Config {
			return config.Config{ShutdownTimeout: shutdownTimeout}
		}
		dependencies.boot = func(config.Config) (*http.Server, contextCleanup, error) {
			return httpServer, func(context.Context) error {
				if !serverConn.closed.Load() {
					prematureCleanup.Store(true)
				}
				cleanupCalls.Add(1)
				return nil
			}, nil
		}
		dependencies.listen = func(*http.Server, config.Config) (net.Listener, bool, error) {
			return listener, false, nil
		}
		runDone := make(chan int, 1)
		go func() { runDone <- run(dependencies) }()
		uploadDone := shutdownTestUpload(clientConn)
		<-uploadStarted
		sendSignal()
		synctest.Wait()
		if serverConn.closed.Load() || cleanupCalls.Load() != 0 {
			t.Fatal("active connection or dependencies closed before the grace timeout")
		}
		time.Sleep(shutdownTimeout)
		if exitCode := <-runDone; exitCode != 0 {
			t.Fatalf("run() exit code = %d, want 0", exitCode)
		}
		<-requestCanceled
		if err := <-uploadDone; err == nil {
			t.Fatal("upload succeeded despite forced connection close")
		}
		if prematureCleanup.Load() {
			t.Error("cleanup ran before the active connection was closed")
		}
		if got := cleanupCalls.Load(); got != 1 {
			t.Fatalf("cleanup calls = %d, want 1", got)
		}
	})
}
