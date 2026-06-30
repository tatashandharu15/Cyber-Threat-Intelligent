// Package api exposes the Alert Engine HTTP endpoints (API Blueprint section 2.10).
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/alert-engine/internal/domain"
	"github.com/siberindo/cti/services/alert-engine/internal/rules"
	"github.com/siberindo/cti/services/alert-engine/internal/store"
)

// Handler holds the Alert Engine endpoint dependencies.
type Handler struct {
	store  *store.Store
	issuer *auth.Issuer
}

// New returns a Handler.
func New(st *store.Store, issuer *auth.Issuer) *Handler {
	return &Handler{store: st, issuer: issuer}
}

// Register wires the alert routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("alert:read"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("alert:update"))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("alert:manage"))
	}

	// Rule CRUD lives under /v1/alert-rules (not /v1/alerts/rules) so the {id}
	// wildcard for alert detail routes cannot collide with the literal "rules"
	// segment in Go's ServeMux.
	mux.Handle("GET /v1/alert-rules", read(h.listRules))
	mux.Handle("POST /v1/alert-rules", manage(h.createRule))
	mux.Handle("PATCH /v1/alert-rules/{id}", manage(h.updateRule))
	mux.Handle("DELETE /v1/alert-rules/{id}", manage(h.deleteRule))

	mux.Handle("GET /v1/alerts", read(h.listAlerts))
	mux.Handle("GET /v1/alerts/metrics", read(h.metrics))
	mux.Handle("GET /v1/alerts/{id}", read(h.getAlert))
	mux.Handle("POST /v1/alerts/{id}/acknowledge", update(h.acknowledge))
	mux.Handle("PATCH /v1/alerts/{id}/status", update(h.updateStatus))
}

func (h *Handler) listAlerts(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	alerts, err := h.store.ListAlerts(r.Context(), tenant, domain.AlertFilter{
		Status: q.Get("status"), Severity: q.Get("severity"), SourceModule: q.Get("source_module"),
		Limit: atoiDefault(q.Get("limit"), 50), Offset: atoiDefault(q.Get("offset"), 0),
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if alerts == nil {
		alerts = []domain.Alert{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, alerts)
}

func (h *Handler) getAlert(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	a, err := h.store.GetAlert(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) acknowledge(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	if err := h.store.Acknowledge(r.Context(), tenant, r.PathValue("id"), auth.ActorID(r.Context())); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "acknowledged"})
}

func (h *Handler) updateStatus(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Status string `json:"status"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validAlertStatus(req.Status) {
		httpx.WriteError(w, r, httpx.NewError(types.ErrValidation, "invalid alert status"))
		return
	}
	if err := h.store.UpdateStatus(r.Context(), tenant, r.PathValue("id"), req.Status, auth.ActorID(r.Context())); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": req.Status})
}

func (h *Handler) listRules(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	rs, err := h.store.ListRules(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if rs == nil {
		rs = []domain.AlertRule{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, rs)
}

type ruleRequest struct {
	Name         string            `json:"name"`
	Description  *string           `json:"description"`
	SourceModule *string           `json:"source_module"`
	Conditions   rules.Conditions  `json:"conditions"`
	WebhookURL   *string           `json:"webhook_url"`
	Status       *string           `json:"status"`
}

func (h *Handler) createRule(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req ruleRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if req.Name == "" {
		httpx.WriteError(w, r, httpx.NewError(types.ErrValidation, "name is required"))
		return
	}
	rule, err := h.store.CreateRule(r.Context(), &domain.AlertRule{
		TenantID: tenant, Name: req.Name, Description: req.Description,
		SourceModule: req.SourceModule, Conditions: req.Conditions, WebhookURL: req.WebhookURL,
	}, auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, rule)
}

func (h *Handler) updateRule(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Name       *string           `json:"name"`
		Status     *string           `json:"status"`
		Conditions *rules.Conditions `json:"conditions"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.store.UpdateRule(r.Context(), tenant, r.PathValue("id"), req.Name, req.Status, req.Conditions, auth.ActorID(r.Context())); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) deleteRule(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	if err := h.store.DeleteRule(r.Context(), tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) metrics(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	m, err := h.store.Metrics(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"open_by_severity": m})
}

func validAlertStatus(s string) bool {
	switch s {
	case "open", "acknowledged", "in_progress", "resolved", "closed", "false_positive":
		return true
	}
	return false
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "alert or rule not found")
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
