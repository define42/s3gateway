package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func TestConfigureSplunkLoggingDisabled(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	handler, err := configureSplunkLogging(config.Config{}, slog.NewJSONHandler(io.Discard, nil))
	if err != nil {
		t.Fatalf("configure disabled Splunk logging: %v", err)
	}
	if handler != nil {
		t.Fatal("disabled Splunk logging should not create a handler")
	}
}

func TestConfigureSplunkLoggingForwardsDefaultLogger(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	requests := make(chan []byte, 1)
	hecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer hecServer.Close()

	var local bytes.Buffer
	handler, err := configureSplunkLogging(config.Config{
		SplunkHECEndpoint:      hecServer.URL,
		SplunkHECToken:         "test-token",
		SplunkHECIndex:         "gateway",
		SplunkHECFlushInterval: time.Hour,
	}, slog.NewJSONHandler(&local, nil))
	if err != nil {
		t.Fatalf("configure Splunk logging: %v", err)
	}
	slog.Info("configured logger event", "component", "app")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Close(ctx); err != nil {
		t.Fatalf("close configured Splunk logger: %v", err)
	}
	if !bytes.Contains(local.Bytes(), []byte(`"msg":"configured logger event"`)) {
		t.Fatalf("local logger did not receive event: %s", local.Bytes())
	}
	select {
	case body := <-requests:
		if !bytes.Contains(body, []byte(`"index":"gateway"`)) ||
			!bytes.Contains(body, []byte(`"msg":"configured logger event"`)) {
			t.Fatalf("Splunk HEC batch mismatch: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Splunk HEC request")
	}
}
