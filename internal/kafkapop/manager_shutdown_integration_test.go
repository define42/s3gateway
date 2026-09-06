//go:build integration

package kafkapop_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestManagerShutdownInterruptsUnavailableBrokerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	broker, stopBroker := testutil.StartRedpanda(ctx, t)
	producer, err := kgo.NewClient(kgo.SeedBrokers(broker))
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	const topic = "shutdown-deadline"
	created, err := kadm.NewClient(producer).CreateTopics(ctx, 1, 1, nil, topic)
	if err != nil {
		t.Fatal(err)
	}
	if err := created[topic].Err; err != nil {
		t.Fatal(err)
	}
	if err := producer.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: []byte("event")}).FirstErr(); err != nil {
		t.Fatal(err)
	}
	manager, err := kafkapop.New(kafkapop.Options{Brokers: []string{broker}, Timeout: 30 * time.Second, IdleTimeout: time.Minute, MaxConsumers: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for i := range 3 {
		if err := manager.Consume(ctx, topic, fmt.Sprintf("shutdown-%d", i), func(*kgo.Record) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// Every consumer has joined and committed before its coordinator disappears.
	stopBroker()
	closeCtx, cancelClose := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelClose()
	started := time.Now()
	err = manager.CloseContext(closeCtx)
	t.Logf("consumer cleanup completed after %s: %v", time.Since(started), err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Kafka cleanup ignored its shared deadline: %s", elapsed)
	}
}
