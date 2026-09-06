// Package kafkaclient owns Kafka client cancellation and shutdown.
package kafkaclient

import (
	"context"
	"sync"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Client releases all Kafka goroutines and connections when closed. Canceling
// the close context interrupts network work before Close waits for it to finish.
type Client struct {
	*kgo.Client
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// New creates a client with an owned lifetime context.
func New(options ...kgo.Opt) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	client, err := kgo.NewClient(append(options, kgo.WithContext(ctx))...)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Client{Client: client, cancel: cancel}, nil
}

// CloseContext permits a graceful group leave until ctx expires, then cancels
// the client's lifetime context to interrupt Kafka I/O. It always joins Close;
// it never leaves a background close running after returning. Concurrent calls
// share one close, and any caller's cancellation can expedite shutdown.
func (c *Client) CloseContext(ctx context.Context) error {
	stop := context.AfterFunc(ctx, c.cancel)
	defer stop()
	if ctx.Err() != nil {
		c.cancel()
	}
	c.closeOnce.Do(func() {
		defer c.cancel()
		c.AllowRebalance()
		c.Client.Close()
	})
	return ctx.Err()
}

// Close waits for Kafka cleanup without an additional deadline.
func (c *Client) Close() {
	_ = c.CloseContext(context.Background())
}
