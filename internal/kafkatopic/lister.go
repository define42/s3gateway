// Package kafkatopic reports Kafka topic statistics for the admin interface.
package kafkatopic

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Topic contains the current offset-based statistics for one Kafka topic.
// Elements is the sum of each partition's end offset minus its start offset.
type Topic struct {
	Name               string
	Partitions         int
	Elements           int64
	IsInternal         bool
	HasUnavailableData bool
}

type adminClient interface {
	ListTopicsWithInternal(context.Context, ...string) (kadm.TopicDetails, error)
	ListStartOffsets(context.Context, ...string) (kadm.ListedOffsets, error)
	ListEndOffsets(context.Context, ...string) (kadm.ListedOffsets, error)
}

var _ adminClient = (*kadm.Client)(nil)

// Lister owns a Kafka admin client and calculates retained topic elements from
// partition start and end offsets.
type Lister struct {
	admin   adminClient
	close   func()
	timeout time.Duration
}

// New creates a topic lister. Kafka connections are established lazily when
// List is first called.
func New(brokers []string, timeout time.Duration) (*Lister, error) {
	if len(brokers) == 0 {
		return nil, errors.New("kafkatopic: at least one kafka broker is required")
	}
	seedBrokers := make([]string, 0, len(brokers))
	for _, broker := range brokers {
		broker = strings.TrimSpace(broker)
		if broker == "" {
			return nil, errors.New("kafkatopic: kafka brokers must not contain empty addresses")
		}
		seedBrokers = append(seedBrokers, broker)
	}
	if timeout <= 0 {
		return nil, errors.New("kafkatopic: timeout must be positive")
	}

	admin, err := kadm.NewOptClient(
		kgo.SeedBrokers(seedBrokers...),
		kgo.ClientID("s3gateway-admin-topics"),
		kgo.RequestTimeoutOverhead(timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("kafkatopic: create kafka admin client: %w", err)
	}
	return newLister(admin, admin.Close, timeout), nil
}

func newLister(admin adminClient, closeClient func(), timeout time.Duration) *Lister {
	return &Lister{
		admin:   admin,
		close:   closeClient,
		timeout: timeout,
	}
}

// Close closes the underlying Kafka client.
func (l *Lister) Close() {
	if l != nil && l.close != nil {
		l.close()
	}
}

// List returns every Kafka topic, including internal topics, ordered by name.
// A non-nil error can accompany partial results when only some brokers or
// partitions fail.
func (l *Lister) List(ctx context.Context) ([]Topic, error) {
	if ctx == nil {
		return nil, errors.New("kafkatopic: context is required")
	}
	if l == nil || l.admin == nil {
		return nil, errors.New("kafkatopic: admin client is not configured")
	}

	listCtx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	details, err := l.admin.ListTopicsWithInternal(listCtx)
	if err != nil {
		return nil, fmt.Errorf("kafkatopic: list topics: %w", err)
	}
	names := details.Names()
	if len(names) == 0 {
		return []Topic{}, nil
	}

	startOffsets, startErr := l.admin.ListStartOffsets(listCtx, names...)
	endOffsets, endErr := l.admin.ListEndOffsets(listCtx, names...)

	topics := make([]Topic, 0, len(names))
	for _, name := range names {
		detail := details[name]
		topic := Topic{
			Name:               name,
			Partitions:         len(detail.Partitions),
			IsInternal:         detail.IsInternal,
			HasUnavailableData: detail.Err != nil,
		}
		for partition := range detail.Partitions {
			start, hasStart := startOffsets.Lookup(name, partition)
			end, hasEnd := endOffsets.Lookup(name, partition)
			if !hasStart || !hasEnd || start.Err != nil || end.Err != nil ||
				start.Offset < 0 || end.Offset < start.Offset {
				topic.HasUnavailableData = true
				continue
			}
			elements := end.Offset - start.Offset
			if elements > math.MaxInt64-topic.Elements {
				topic.HasUnavailableData = true
				continue
			}
			topic.Elements += elements
		}
		topics = append(topics, topic)
	}

	var offsetErrors []error
	if startErr != nil {
		offsetErrors = append(offsetErrors, fmt.Errorf("list start offsets: %w", startErr))
	}
	if endErr != nil {
		offsetErrors = append(offsetErrors, fmt.Errorf("list end offsets: %w", endErr))
	}
	return topics, errors.Join(offsetErrors...)
}
