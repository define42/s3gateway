package adminpage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/kafkatopic"
)

type kafkaTopicListerStub struct {
	topics []kafkatopic.Topic
	err    error
	calls  int
}

func (s *kafkaTopicListerStub) List(context.Context) ([]kafkatopic.Topic, error) {
	s.calls++
	return s.topics, s.err
}

func TestAdminKafkaTopics(t *testing.T) {
	tests := []struct {
		name            string
		lister          *kafkaTopicListerStub
		method          string
		isAuthenticated bool
		wantStatus      int
		wantBody        []string
		wantBodyCount   map[string]int
		wantCalls       int
	}{
		{
			name: "renders topic counts",
			lister: &kafkaTopicListerStub{topics: []kafkatopic.Topic{
				{Name: "__consumer_offsets", Partitions: 3, Elements: 7, IsInternal: true},
				{
					Name:       "_all",
					Partitions: 1,
					Elements:   42,
					ConsumerGroups: []kafkatopic.ConsumerGroup{{
						Name:  "testuser:testgroup",
						State: "Empty",
						Offsets: []kafkatopic.ConsumerGroupOffset{{
							Partition:     0,
							CurrentOffset: 17,
							IsCommitted:   true,
						}},
					}},
				},
			}},
			method:          http.MethodGet,
			isAuthenticated: true,
			wantStatus:      http.StatusOK,
			wantBody: []string{
				"Kafka Topics",
				`href="/admin"`,
				`href="/admin/kafka-topics" aria-current="page"`,
				"__consumer_offsets",
				"_all",
				"<code>42</code>",
				"Internal",
				"Application",
				"Consumer groups",
				"testuser:testgroup",
				`aria-label="Partition 0, current offset 17"`,
				"<code>17</code>",
			},
			wantBodyCount: map[string]int{"Consumer groups": 1},
			wantCalls:     1,
		},
		{
			name: "renders partial offset failure",
			lister: &kafkaTopicListerStub{
				topics: []kafkatopic.Topic{{
					Name:               "_all",
					Partitions:         1,
					HasUnavailableData: true,
				}},
				err: errors.New("broker unavailable"),
			},
			method:          http.MethodGet,
			isAuthenticated: true,
			wantStatus:      http.StatusBadGateway,
			wantBody: []string{
				"Some Kafka topic or consumer-group offsets could not be loaded.",
				"_all",
				"Unavailable",
			},
			wantCalls: 1,
		},
		{
			name: "renders unavailable and uncommitted consumer offsets",
			lister: &kafkaTopicListerStub{topics: []kafkatopic.Topic{
				{
					Name:                         "uploads",
					Partitions:                   2,
					Elements:                     10,
					HasUnavailableConsumerGroups: true,
					ConsumerGroups: []kafkatopic.ConsumerGroup{{
						Name:  "scanner",
						State: "Stable",
						Offsets: []kafkatopic.ConsumerGroupOffset{
							{Partition: 0, HasUnavailableData: true},
							{Partition: 1, CurrentOffset: -1},
						},
					}},
				},
				{Name: "without-consumers", Partitions: 1},
			}},
			method:          http.MethodGet,
			isAuthenticated: true,
			wantStatus:      http.StatusOK,
			wantBody: []string{
				"Some offsets unavailable",
				`aria-label="Partition 0, offset unavailable"`,
				`aria-label="Partition 1, not committed"`,
				"without-consumers",
				">None<",
			},
			wantCalls: 1,
		},
		{
			name:       "redirects unauthenticated user",
			lister:     &kafkaTopicListerStub{},
			method:     http.MethodGet,
			wantStatus: http.StatusSeeOther,
			wantCalls:  0,
		},
		{
			name:            "rejects unsupported method",
			lister:          &kafkaTopicListerStub{},
			method:          http.MethodPost,
			isAuthenticated: true,
			wantStatus:      http.StatusMethodNotAllowed,
			wantCalls:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerWithNilS3(map[string]struct{}{"team2-r": {}})
			h.kafkaTopicLister = tt.lister
			req := httptest.NewRequest(tt.method, "/admin/kafka-topics", nil)
			if tt.isAuthenticated {
				req.AddCookie(adminLoginSessionCookie(t, h, "alice", "secret"))
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", rr.Code, tt.wantStatus, rr.Body.String())
			}
			for _, want := range tt.wantBody {
				if !strings.Contains(rr.Body.String(), want) {
					t.Fatalf("body missing %q: %q", want, rr.Body.String())
				}
			}
			for text, want := range tt.wantBodyCount {
				if got := strings.Count(rr.Body.String(), text); got != want {
					t.Fatalf("body count for %q = %d, want %d: %q", text, got, want, rr.Body.String())
				}
			}
			if tt.lister.calls != tt.wantCalls {
				t.Fatalf("lister calls = %d, want %d", tt.lister.calls, tt.wantCalls)
			}
		})
	}
}

func TestAdminKafkaTopicsNotConfigured(t *testing.T) {
	h := newHandlerWithNilS3(map[string]struct{}{"team2-r": {}})
	req := httptest.NewRequest(http.MethodGet, "/admin/kafka-topics", nil)
	req.AddCookie(adminLoginSessionCookie(t, h, "alice", "secret"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "Kafka integration is not configured.") {
		t.Fatalf("missing configuration message: %q", rr.Body.String())
	}
}

func TestAdminKafkaTopicsHead(t *testing.T) {
	h := newHandlerWithNilS3(map[string]struct{}{"team2-r": {}})
	lister := &kafkaTopicListerStub{}
	h.kafkaTopicLister = lister
	req := httptest.NewRequest(http.MethodHead, "/admin/kafka-topics", nil)
	req.AddCookie(adminLoginSessionCookie(t, h, "alice", "secret"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("HEAD body length = %d, want 0", rr.Body.Len())
	}
}

func TestWithKafkaTopicLister(t *testing.T) {
	lister := &kafkaTopicListerStub{}
	got := NewHandlerWithContext(nil, "secret", 1, nil, nil, WithKafkaTopicLister(lister))
	h, ok := got.(*handler)
	if !ok {
		t.Fatalf("handler type = %T, want *handler", got)
	}
	if h.kafkaTopicLister != lister {
		t.Fatal("Kafka topic lister option was not applied")
	}
}
