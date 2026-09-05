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
	// IdleTimeout bounds group membership after the last active or queued call.
	// Zero uses 30 seconds.
	IdleTimeout time.Duration
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
	key            consumerKey
	gate           chan struct{} // A single permit serializes polling, handling, and closing.
	client         consumerClient
	lastUsed       time.Time
	users          int
	idleTimer      *time.Timer // Protected by Manager.mu, like users and lastUsed.
	idleGeneration uint64
}

// Manager owns a bounded cache of Kafka group consumers. Calls for the same
// topic and group are serialized so offsets are processed and committed in
// order. Idle consumers leave their Kafka group after the idle timeout, or
// earlier when the cache is full, so other replicas can take their partitions.
type Manager struct {
	mu           sync.Mutex
	consumers    map[consumerKey]*groupConsumer
	newClient    clientFactory
	timeout      time.Duration
	idleTimeout  time.Duration
	maxConsumers int
	isClosed     bool
	closed       chan struct{}
	closeDone    chan struct{}
	closers      sync.WaitGroup // Timers and detached clients; additions require mu.
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
	if options.IdleTimeout < 0 {
		return nil, errors.New("kafkapop: idle timeout must be positive")
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = 30 * time.Second
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

	return newManager(options.Timeout, options.IdleTimeout, options.MaxConsumers, factory), nil
}

func newManager(timeout, idleTimeout time.Duration, maxConsumers int, factory clientFactory) *Manager {
	return &Manager{
		consumers:    make(map[consumerKey]*groupConsumer),
		newClient:    factory,
		timeout:      timeout,
		idleTimeout:  idleTimeout,
		maxConsumers: maxConsumers,
		closed:       make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
}

// Consume polls one record, calls handle, and synchronously commits the record
// only when handle succeeds. A failed poll, handler, or commit rewinds any
// returned record's local partition position so it remains eligible for
// redelivery. Waiting for another call on the same topic and group respects
// ctx cancellation.
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

	consumer, err := m.acquire(ctx, topic, group)
	if err != nil {
		return err
	}
	defer func() {
		<-consumer.gate
		m.release(consumer)
	}()

	pollCtx, cancelPoll := context.WithTimeout(ctx, m.timeout)
	fetches := consumer.client.PollRecords(pollCtx, 1)
	// Polling can block rebalances even when it returns no records or an error.
	defer consumer.client.AllowRebalance()
	cancelPoll()

	records := fetches.Records()
	if err := fetches.Err(); err != nil {
		// PollRecords can advance one record even when another partition fails.
		// Rewind it before returning the error and allowing a rebalance.
		if len(records) > 0 {
			rewindRecord(consumer.client, records[0])
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return ErrNoEvent
		}
		return fmt.Errorf("kafkapop: poll record: %w", err)
	}
	if len(records) == 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("kafkapop: poll record: %w", err)
		}
		return ErrNoEvent
	}

	record := records[0]
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

func (m *Manager) acquire(ctx context.Context, topic, group string) (*groupConsumer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := consumerKey{topic: topic, group: group}
	now := time.Now()

	m.mu.Lock()
	if m.isClosed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	if consumer := m.consumers[key]; consumer != nil {
		m.stopIdleTimer(consumer)
		consumer.users++
		consumer.lastUsed = now
		m.mu.Unlock()
		return m.waitForConsumer(ctx, consumer)
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
		key:      key,
		gate:     make(chan struct{}, 1),
		client:   client,
		lastUsed: now,
		users:    1,
	}
	if evicted != nil {
		m.stopIdleTimer(evicted)
		m.closers.Add(1)
		delete(m.consumers, evictionKey)
	}
	m.consumers[key] = consumer
	m.mu.Unlock()

	if evicted != nil {
		evicted.client.CloseAllowingRebalance()
		m.closers.Done()
	}
	return m.waitForConsumer(ctx, consumer)
}

// waitForConsumer is called after pinning the consumer under m.mu. Waiting
// outside that lock lets other groups progress and keeps cancellation prompt.
func (m *Manager) waitForConsumer(ctx context.Context, consumer *groupConsumer) (*groupConsumer, error) {
	select {
	case consumer.gate <- struct{}{}:
	case <-ctx.Done():
		m.release(consumer)
		return nil, ctx.Err()
	case <-m.closed:
		m.release(consumer)
		return nil, ErrClosed
	}

	// A permit and cancellation can become ready together. Check again before
	// allowing any client use; Close also acquires the permit before closing it.
	err := ctx.Err()
	m.mu.Lock()
	if m.isClosed {
		err = ErrClosed
	}
	m.mu.Unlock()
	if err != nil {
		<-consumer.gate
		m.release(consumer)
		return nil, err
	}
	return consumer, nil
}

func (m *Manager) release(consumer *groupConsumer) {
	m.mu.Lock()
	if consumer.users > 0 {
		consumer.users--
	}
	consumer.lastUsed = time.Now()
	if consumer.users == 0 && !m.isClosed {
		m.closers.Add(1)
		consumer.idleGeneration++
		generation := consumer.idleGeneration
		consumer.idleTimer = time.AfterFunc(m.idleTimeout, func() {
			defer m.closers.Done()
			m.expireConsumer(consumer, generation)
		})
	}
	m.mu.Unlock()
}

// stopIdleTimer requires m.mu. A callback that has already started owns its
// wait-group reference and checks that its idle generation is still current.
func (m *Manager) stopIdleTimer(consumer *groupConsumer) {
	if consumer.idleTimer != nil {
		if consumer.idleTimer.Stop() {
			m.closers.Done()
		}
		consumer.idleTimer = nil
	}
}

func (m *Manager) expireConsumer(consumer *groupConsumer, generation uint64) {
	m.mu.Lock()
	if m.isClosed || consumer.users != 0 || consumer.idleTimer == nil ||
		consumer.idleGeneration != generation || m.consumers[consumer.key] != consumer {
		m.mu.Unlock()
		return
	}
	delete(m.consumers, consumer.key)
	consumer.idleTimer = nil
	m.mu.Unlock()

	// No users can acquire the detached client. Closing outside mu lets other
	// groups and idle timers progress while Kafka processes the leave request.
	consumer.client.CloseAllowingRebalance()
}

// Close rejects queued calls and closes every cached Kafka client. It waits
// for in-progress callbacks and any idle eviction already closing a client.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.isClosed {
		m.mu.Unlock()
		<-m.closeDone
		return
	}
	m.isClosed = true
	close(m.closed)
	consumers := make([]*groupConsumer, 0, len(m.consumers))
	for _, consumer := range m.consumers {
		m.stopIdleTimer(consumer)
		consumers = append(consumers, consumer)
	}
	m.consumers = nil
	m.mu.Unlock()

	for _, consumer := range consumers {
		consumer.gate <- struct{}{}
		consumer.client.CloseAllowingRebalance()
		<-consumer.gate
	}
	m.closers.Wait()
	close(m.closeDone)
}
