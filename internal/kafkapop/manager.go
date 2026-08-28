// Package kafkapop consumes upload events for the object pop HTTP API.
package kafkapop

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

var (
	// ErrNoEvent indicates that no record became available before the poll
	// timeout elapsed.
	ErrNoEvent = errors.New("kafkapop: no event available")
	// ErrConsumerLimit indicates that every cached consumer is currently in use.
	ErrConsumerLimit = errors.New("kafkapop: consumer limit reached")
	// ErrClosed indicates that the manager has begun shutting down.
	ErrClosed = errors.New("kafkapop: manager closed")
)

// Options configures a Manager.
type Options struct {
	Brokers      []string
	Timeout      time.Duration
	MaxConsumers int
}

type consumerClient interface {
	PollRecords(context.Context, int) kgo.Fetches
	CommitRecords(context.Context, ...*kgo.Record) error
	SetOffsets(map[string]map[int32]kgo.EpochOffset)
	AllowRebalance()
	CloseAllowingRebalance()
}

var _ consumerClient = (*kgo.Client)(nil)

type clientFactory func(topic, group string) (consumerClient, error)

type consumerKey struct {
	topic string
	group string
}

type groupConsumer struct {
	mu       sync.Mutex
	client   consumerClient
	lastUsed time.Time
	users    int
}

// Manager owns a bounded cache of Kafka group consumers. Calls for the same
// topic and group are serialized so offsets are processed and committed in
// order. Idle consumers are evicted on demand when the cache is full.
type Manager struct {
	mu           sync.Mutex
	consumers    map[consumerKey]*groupConsumer
	newClient    clientFactory
	timeout      time.Duration
	maxConsumers int
	isClosed     bool
}

// New constructs a Kafka pop manager. Kafka connections and group joins are
// established lazily by the first request for each topic and group.
func New(options Options) (*Manager, error) {
	if len(options.Brokers) == 0 {
		return nil, errors.New("kafkapop: at least one kafka broker is required")
	}
	for _, broker := range options.Brokers {
		if strings.TrimSpace(broker) == "" {
			return nil, errors.New("kafkapop: kafka brokers must not contain empty addresses")
		}
	}
	if options.Timeout <= 0 {
		return nil, errors.New("kafkapop: timeout must be positive")
	}
	if options.MaxConsumers <= 0 {
		return nil, errors.New("kafkapop: max consumers must be positive")
	}

	fetchMaxWait := min(options.Timeout, 5*time.Second)
	factory := func(topic, group string) (consumerClient, error) {
		client, err := kgo.NewClient(
			kgo.SeedBrokers(options.Brokers...),
			kgo.ClientID("s3gateway-pop"),
			kgo.ConsumerGroup(group),
			kgo.ConsumeTopics(topic),
			kgo.DisableAutoCommit(),
			kgo.BlockRebalanceOnPoll(),
			kgo.FetchIsolationLevel(kgo.ReadCommitted()),
			kgo.FetchMaxWait(fetchMaxWait),
			kgo.FetchMaxBytes(1<<20),
			kgo.FetchMaxPartitionBytes(1<<20),
			kgo.MaxConcurrentFetches(1),
		)
		if err != nil {
			return nil, fmt.Errorf("kafkapop: create kafka client: %w", err)
		}
		return client, nil
	}

	return newManager(options.Timeout, options.MaxConsumers, factory), nil
}

func newManager(timeout time.Duration, maxConsumers int, factory clientFactory) *Manager {
	return &Manager{
		consumers:    make(map[consumerKey]*groupConsumer),
		newClient:    factory,
		timeout:      timeout,
		maxConsumers: maxConsumers,
	}
}

// Consume polls one record, calls handle, and synchronously commits the record
// only when handle succeeds. A failed handler or commit rewinds the local
// partition position so the record remains eligible for redelivery.
func (m *Manager) Consume(
	ctx context.Context,
	topic string,
	group string,
	handle func(*kgo.Record) error,
) error {
	if ctx == nil {
		return errors.New("kafkapop: context is required")
	}
	if strings.TrimSpace(topic) == "" {
		return errors.New("kafkapop: topic is required")
	}
	if strings.TrimSpace(group) == "" {
		return errors.New("kafkapop: group is required")
	}
	if handle == nil {
		return errors.New("kafkapop: record handler is required")
	}

	consumer, err := m.acquire(topic, group)
	if err != nil {
		return err
	}
	defer m.release(consumer)

	consumer.mu.Lock()
	defer consumer.mu.Unlock()

	pollCtx, cancelPoll := context.WithTimeout(ctx, m.timeout)
	fetches := consumer.client.PollRecords(pollCtx, 1)
	cancelPoll()

	if err := fetches.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return ErrNoEvent
		}
		return fmt.Errorf("kafkapop: poll record: %w", err)
	}
	records := fetches.Records()
	if len(records) == 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("kafkapop: poll record: %w", err)
		}
		return ErrNoEvent
	}

	record := records[0]
	defer consumer.client.AllowRebalance()
	if err := handle(record); err != nil {
		rewindRecord(consumer.client, record)
		return fmt.Errorf("kafkapop: handle record: %w", err)
	}

	commitCtx, cancelCommit := context.WithTimeout(
		context.WithoutCancel(ctx),
		m.timeout,
	)
	defer cancelCommit()
	if err := consumer.client.CommitRecords(commitCtx, record); err != nil {
		rewindRecord(consumer.client, record)
		return fmt.Errorf("kafkapop: commit record: %w", err)
	}
	return nil
}

func rewindRecord(client consumerClient, record *kgo.Record) {
	client.SetOffsets(map[string]map[int32]kgo.EpochOffset{
		record.Topic: {
			record.Partition: {
				Epoch:  record.LeaderEpoch,
				Offset: record.Offset,
			},
		},
	})
}

func (m *Manager) acquire(topic, group string) (*groupConsumer, error) {
	key := consumerKey{topic: topic, group: group}
	now := time.Now()

	m.mu.Lock()
	if m.isClosed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	if consumer := m.consumers[key]; consumer != nil {
		consumer.users++
		consumer.lastUsed = now
		m.mu.Unlock()
		return consumer, nil
	}

	var evictionKey consumerKey
	var evicted *groupConsumer
	if len(m.consumers) >= m.maxConsumers {
		for candidateKey, candidate := range m.consumers {
			if candidate.users != 0 {
				continue
			}
			if evicted == nil || candidate.lastUsed.Before(evicted.lastUsed) {
				evictionKey = candidateKey
				evicted = candidate
			}
		}
		if evicted == nil {
			m.mu.Unlock()
			return nil, ErrConsumerLimit
		}
	}

	client, err := m.newClient(topic, group)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("kafkapop: initialize consumer: %w", err)
	}
	consumer := &groupConsumer{
		client:   client,
		lastUsed: now,
		users:    1,
	}
	if evicted != nil {
		delete(m.consumers, evictionKey)
	}
	m.consumers[key] = consumer
	m.mu.Unlock()

	if evicted != nil {
		evicted.client.CloseAllowingRebalance()
	}
	return consumer, nil
}

func (m *Manager) release(consumer *groupConsumer) {
	m.mu.Lock()
	if consumer.users > 0 {
		consumer.users--
	}
	consumer.lastUsed = time.Now()
	m.mu.Unlock()
}

// Close prevents new consumers and closes every cached Kafka client. It waits
// for an in-progress callback to finish before closing that callback's client.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.isClosed {
		m.mu.Unlock()
		return
	}
	m.isClosed = true
	consumers := make([]*groupConsumer, 0, len(m.consumers))
	for _, consumer := range m.consumers {
		consumers = append(consumers, consumer)
	}
	m.consumers = nil
	m.mu.Unlock()

	for _, consumer := range consumers {
		consumer.mu.Lock()
		consumer.client.CloseAllowingRebalance()
		consumer.mu.Unlock()
	}
}
