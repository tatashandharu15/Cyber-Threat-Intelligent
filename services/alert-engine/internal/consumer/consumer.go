// Package consumer turns escalated-finding events into alerts. It is the Kafka
// side of the Alert Engine: for each finding.escalated.* event it loads the
// tenant's active rules, evaluates them, and creates an alert (and an
// alert.created event) for every match.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/alert-engine/internal/domain"
	"github.com/siberindo/cti/services/alert-engine/internal/events"
	"github.com/siberindo/cti/services/alert-engine/internal/rules"
)

// Store is the persistence contract the consumer needs.
type Store interface {
	ListActiveRules(ctx context.Context, tenantID string) ([]rules.Rule, error)
	CreateAlert(ctx context.Context, a *domain.Alert) (*domain.Alert, error)
}

// Handler processes escalated-finding events.
type Handler struct {
	store Store
	pub   events.Publisher
	log   *slog.Logger
}

// New constructs a Handler.
func New(store Store, pub events.Publisher, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{store: store, pub: pub, log: log}
}

// Handle is the kafka.Handler entry point. Returning an error triggers a retry, so
// only infrastructure failures (DB, unmarshal of a well-formed-but-unreadable
// payload) return errors; a finding that matches no rules is a successful no-op.
func (h *Handler) Handle(ctx context.Context, _, value []byte) error {
	var ev types.FindingEscalated
	if err := json.Unmarshal(value, &ev); err != nil {
		// A malformed message will never succeed on retry; log and drop it.
		h.log.ErrorContext(ctx, "drop unparseable finding.escalated event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.FindingID == "" {
		h.log.WarnContext(ctx, "drop finding.escalated event missing tenant or finding id")
		return nil
	}

	activeRules, err := h.store.ListActiveRules(ctx, ev.TenantID)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	matched := rules.Evaluate(activeRules, ev)
	if len(matched) == 0 {
		h.log.InfoContext(ctx, "no alert rules matched",
			slog.String("tenant_id", ev.TenantID), slog.String("finding_id", ev.FindingID))
		return nil
	}

	for _, rule := range matched {
		ruleID := rule.ID
		title := ev.Title
		if title == "" {
			title = fmt.Sprintf("%s finding escalated", ev.SourceModule)
		}
		alert, err := h.store.CreateAlert(ctx, &domain.Alert{
			TenantID: ev.TenantID, AlertRuleID: &ruleID, SourceModule: string(ev.SourceModule),
			SourceFindingID: ev.FindingID, Title: title, Severity: string(ev.Severity),
		})
		if err != nil {
			return fmt.Errorf("create alert: %w", err)
		}
		h.publish(ctx, types.AlertCreated{
			EventID: newEventID(), EventType: "alert.created", TenantID: ev.TenantID,
			AlertID: alert.ID, SourceModule: ev.SourceModule, SourceFindingID: ev.FindingID,
			Severity: ev.Severity, Title: title, CreatedAt: time.Now(),
		})
	}
	return nil
}

func (h *Handler) publish(ctx context.Context, alert types.AlertCreated) {
	if h.pub == nil {
		return
	}
	if err := h.pub.Publish(ctx, types.TopicAlertCreated, alert.TenantID, alert); err != nil {
		h.log.WarnContext(ctx, "alert.created publish failed", slog.String("error", err.Error()))
	}
}
