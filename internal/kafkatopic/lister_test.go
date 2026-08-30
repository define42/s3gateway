package kafkatopic

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
)

type adminClientStub struct {
	details      kadm.TopicDetails
	detailsErr   error
	startOffsets kadm.ListedOffsets
	startErr     error
	endOffsets   kadm.ListedOffsets
	endErr       error
	groups       kadm.ListedGroups
	groupsErr    error
	fetched      kadm.FetchOffsetsResponses
	requested    []string
	groupRequest []string
}

func (s *adminClientStub) ListTopicsWithInternal(context.Context, ...string) (kadm.TopicDetails, error) {
	return s.details, s.detailsErr
}

func (s *adminClientStub) ListStartOffsets(_ context.Context, topics ...string) (kadm.ListedOffsets, error) {
	s.requested = append([]string(nil), topics...)
	return s.startOffsets, s.startErr
}

func (s *adminClientStub) ListEndOffsets(_ context.Context, topics ...string) (kadm.ListedOffsets, error) {
	return s.endOffsets, s.endErr
}

func (s *adminClientStub) ListGroups(context.Context, ...string) (kadm.ListedGroups, error) {
	return s.groups, s.groupsErr
}

func (s *adminClientStub) FetchManyOffsets(_ context.Context, groups ...string) kadm.FetchOffsetsResponses {
	s.groupRequest = append([]string(nil), groups...)
	return s.fetched
}

func TestListerList(t *testing.T) {
	tests := []struct {
		name        string
		stub        *adminClientStub
		want        []Topic
		wantErr     bool
		wantRequest []string
		wantGroups  []string
	}{
		{
			name: "counts retained elements and sorts topics",
			stub: &adminClientStub{
				details: kadm.TopicDetails{
					"uploads": {
						Topic: "uploads",
						Partitions: kadm.PartitionDetails{
							0: {Topic: "uploads", Partition: 0},
							1: {Topic: "uploads", Partition: 1},
						},
					},
					"__consumer_offsets": {
						Topic:      "__consumer_offsets",
						IsInternal: true,
						Partitions: kadm.PartitionDetails{
							0: {Topic: "__consumer_offsets", Partition: 0},
						},
					},
				},
				startOffsets: kadm.ListedOffsets{
					"uploads": {
						0: {Topic: "uploads", Partition: 0, Offset: 4},
						1: {Topic: "uploads", Partition: 1, Offset: 10},
					},
					"__consumer_offsets": {
						0: {Topic: "__consumer_offsets", Partition: 0, Offset: 2},
					},
				},
				endOffsets: kadm.ListedOffsets{
					"uploads": {
						0: {Topic: "uploads", Partition: 0, Offset: 9},
						1: {Topic: "uploads", Partition: 1, Offset: 17},
					},
					"__consumer_offsets": {
						0: {Topic: "__consumer_offsets", Partition: 0, Offset: 5},
					},
				},
				groups: kadm.ListedGroups{
					"testuser:testgroup": {
						Group:        "testuser:testgroup",
						ProtocolType: "consumer",
						State:        "Empty",
					},
					"analytics": {
						Group:        "analytics",
						ProtocolType: "consumer",
						State:        "Stable",
					},
				},
				fetched: kadm.FetchOffsetsResponses{
					"testuser:testgroup": {
						Group: "testuser:testgroup",
						Fetched: kadm.OffsetResponses{
							"uploads": {
								0: {Offset: kadm.Offset{Topic: "uploads", Partition: 0, At: 9}},
							},
						},
					},
					"analytics": {
						Group: "analytics",
						Fetched: kadm.OffsetResponses{
							"uploads": {
								1: {Offset: kadm.Offset{Topic: "uploads", Partition: 1, At: 13}},
							},
						},
					},
				},
			},
			want: []Topic{
				{Name: "__consumer_offsets", Partitions: 1, Elements: 3, IsInternal: true},
				{
					Name:       "uploads",
					Partitions: 2,
					Elements:   12,
					ConsumerGroups: []ConsumerGroup{
						{
							Name:  "analytics",
							State: "Stable",
							Offsets: []ConsumerGroupOffset{{
								Partition:     1,
								CurrentOffset: 13,
								IsCommitted:   true,
							}},
						},
						{
							Name:  "testuser:testgroup",
							State: "Empty",
							Offsets: []ConsumerGroupOffset{{
								Partition:     0,
								CurrentOffset: 9,
								IsCommitted:   true,
							}},
						},
					},
				},
			},
			wantRequest: []string{"__consumer_offsets", "uploads"},
			wantGroups:  []string{"analytics", "testuser:testgroup"},
		},
		{
			name: "returns partial topics with unavailable offsets",
			stub: &adminClientStub{
				details: kadm.TopicDetails{
					"uploads": {
						Topic: "uploads",
						Partitions: kadm.PartitionDetails{
							0: {Topic: "uploads", Partition: 0},
							1: {Topic: "uploads", Partition: 1},
						},
					},
				},
				startOffsets: kadm.ListedOffsets{
					"uploads": {0: {Topic: "uploads", Partition: 0, Offset: 1}},
				},
				endOffsets: kadm.ListedOffsets{
					"uploads": {0: {Topic: "uploads", Partition: 0, Offset: 4}},
				},
				endErr: errors.New("broker unavailable"),
			},
			want: []Topic{{
				Name:               "uploads",
				Partitions:         2,
				Elements:           3,
				HasUnavailableData: true,
			}},
			wantErr:     true,
			wantRequest: []string{"uploads"},
		},
		{
			name: "returns topic data when consumer groups are unavailable",
			stub: &adminClientStub{
				details: kadm.TopicDetails{
					"uploads": {
						Topic: "uploads",
						Partitions: kadm.PartitionDetails{
							0: {Topic: "uploads", Partition: 0},
						},
					},
				},
				startOffsets: kadm.ListedOffsets{
					"uploads": {0: {Topic: "uploads", Partition: 0, Offset: 1}},
				},
				endOffsets: kadm.ListedOffsets{
					"uploads": {0: {Topic: "uploads", Partition: 0, Offset: 4}},
				},
				groupsErr: errors.New("coordinator unavailable"),
			},
			want: []Topic{{
				Name:                         "uploads",
				Partitions:                   1,
				Elements:                     3,
				HasUnavailableConsumerGroups: true,
			}},
			wantErr:     true,
			wantRequest: []string{"uploads"},
		},
		{
			name: "returns topic metadata error",
			stub: &adminClientStub{
				detailsErr: errors.New("metadata unavailable"),
			},
			wantErr: true,
		},
		{
			name: "returns empty list without offset requests",
			stub: &adminClientStub{
				details: kadm.TopicDetails{},
			},
			want: []Topic{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := newLister(tt.stub, nil, time.Second)
			got, err := lister.List(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("List() error = %v, want error = %t", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("List() topic count = %d, want %d: %+v", len(got), len(tt.want), got)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("List() = %+v, want %+v", got, tt.want)
			}
			if len(tt.stub.requested) != len(tt.wantRequest) {
				t.Fatalf("requested topics = %v, want %v", tt.stub.requested, tt.wantRequest)
			}
			for i := range tt.wantRequest {
				if tt.stub.requested[i] != tt.wantRequest[i] {
					t.Fatalf("requested topics = %v, want %v", tt.stub.requested, tt.wantRequest)
				}
			}
			if !reflect.DeepEqual(tt.stub.groupRequest, tt.wantGroups) {
				t.Fatalf("requested groups = %v, want %v", tt.stub.groupRequest, tt.wantGroups)
			}
		})
	}
}

func TestListerClose(t *testing.T) {
	closed := false
	lister := newLister(&adminClientStub{}, func() { closed = true }, time.Second)
	lister.Close()
	if !closed {
		t.Fatal("Close() did not close the Kafka admin client")
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		brokers []string
		timeout time.Duration
	}{
		{name: "missing brokers", timeout: time.Second},
		{name: "empty broker", brokers: []string{"broker:9092", " "}, timeout: time.Second},
		{name: "invalid timeout", brokers: []string{"broker:9092"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister, err := New(tt.brokers, tt.timeout)
			if err == nil {
				lister.Close()
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}
