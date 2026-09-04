package adminpage

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/kafkatopic"
)

type adminKafkaTopicsPageData struct {
	Username          string
	Error             string
	GeneratedAt       string
	Topics            []kafkatopic.Topic
	TotalTopics       int
	KnownElements     int64
	UnavailableTopics int
}

func visibleAdminKafkaTopics(
	topics []kafkatopic.Topic,
	rules []authz.Rule,
	globalTopic string,
) []kafkatopic.Topic {
	if authz.CanReadAll(rules) {
		return topics
	}

	globalTopic = strings.TrimSpace(globalTopic)
	visible := make([]kafkatopic.Topic, 0, len(topics))
	for _, topic := range topics {
		if topic.IsInternal || topic.Name == "_all" ||
			(globalTopic != "" && topic.Name == globalTopic) {
			continue
		}
		if authz.CanRead(rules, topic.Name) {
			visible = append(visible, topic)
		}
	}
	return visible
}

func writeAdminKafkaTopicsPage(w http.ResponseWriter, r *http.Request, status int, data adminKafkaTopicsPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = adminKafkaTopicsTmpl.Execute(w, data)
}

func (h *handler) handleAdminKafkaTopics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rules := authz.RulesFromGroups(session.Groups)

	data := adminKafkaTopicsPageData{
		Username:    session.Username,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if h == nil || h.kafkaTopicLister == nil {
		data.Error = "Kafka integration is not configured."
		writeAdminKafkaTopicsPage(w, r, http.StatusServiceUnavailable, data)
		return
	}

	topics, err := h.kafkaTopicLister.List(r.Context())
	topics = visibleAdminKafkaTopics(topics, rules, h.kafkaGlobalTopic)
	data.Topics = topics
	data.TotalTopics = len(topics)
	for _, topic := range topics {
		if topic.HasUnavailableData || topic.HasUnavailableConsumerGroups {
			data.UnavailableTopics++
		}
		if topic.HasUnavailableData {
			continue
		}
		data.KnownElements += topic.Elements
	}
	if err != nil {
		slog.WarnContext(r.Context(), "failed to list kafka topic offsets", "error", err)
		if len(topics) == 0 {
			data.Error = "Could not load Kafka topics."
		} else {
			data.Error = "Some Kafka topic or consumer-group offsets could not be loaded."
		}
		writeAdminKafkaTopicsPage(w, r, http.StatusBadGateway, data)
		return
	}

	writeAdminKafkaTopicsPage(w, r, http.StatusOK, data)
}
