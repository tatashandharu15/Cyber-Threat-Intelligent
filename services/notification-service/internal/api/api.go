// Package api exposes the Notification Center HTTP endpoints.
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/notification-service/internal/domain"
	"github.com/siberindo/cti/services/notification-service/internal/service"
	"github.com/siberindo/cti/services/notification-service/internal/store"
)

// Handler holds the Notification endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Notification routes onto mux. Every route requires a valid
// token plus the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("notification:read"))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("notification:manage"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("notification:update"))
	}

	mux.Handle("GET /v1/notifications", read(h.listNotifications))
	mux.Handle("POST /v1/notifications", manage(h.createNotification))
	mux.Handle("GET /v1/notifications/{id}", read(h.getNotification))
	mux.Handle("POST /v1/notifications/{id}/read", update(h.markRead))

	mux.Handle("GET /v1/notification-preferences", read(h.listPreferences))
	mux.Handle("PUT /v1/notification-preferences", update(h.setPreference))
}

func (h *Handler) listNotifications(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.NotificationFilter{
		Status:          q.Get("status"),
		Channel:         q.Get("channel"),
		RecipientUserID: q.Get("recipient_user_id"),
		Limit:           atoiDefault(q.Get("limit"), 50),
		Offset:          atoiDefault(q.Get("offset"), 0),
	}
	notifications, err := h.svc.ListNotifications(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if notifications == nil {
		notifications = []domain.Notification{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, notifications)
}

type createNotificationRequest struct {
	Channel         string  `json:"channel"`
	EventType       string  `json:"event_type"`
	Subject         *string `json:"subject"`
	Body            *string `json:"body"`
	RecipientUserID *string `json:"recipient_user_id"`
	ReferenceType   *string `json:"reference_type"`
	ReferenceID     *string `json:"reference_id"`
	Severity        *string `json:"severity"`
}

func (h *Handler) createNotification(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createNotificationRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	n, err := h.svc.CreateNotification(ctx, tenant, service.CreateNotificationInput{
		Channel: req.Channel, EventType: req.EventType, Subject: req.Subject, Body: req.Body,
		RecipientUserID: req.RecipientUserID, ReferenceType: req.ReferenceType,
		ReferenceID: req.ReferenceID, Severity: req.Severity,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, n)
}

func (h *Handler) getNotification(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	n, err := h.svc.GetNotification(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, n)
}

func (h *Handler) markRead(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.MarkRead(ctx, tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "read"})
}

func (h *Handler) listPreferences(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = auth.ActorID(r.Context())
	}
	prefs, err := h.svc.ListPreferences(r.Context(), tenant, userID)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if prefs == nil {
		prefs = []domain.Preference{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, prefs)
}

func (h *Handler) setPreference(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		UserID    string `json:"user_id"`
		Channel   string `json:"channel"`
		EventType string `json:"event_type"`
		Enabled   bool   `json:"enabled"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID := req.UserID
	if userID == "" {
		userID = auth.ActorID(r.Context())
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	p, err := h.svc.SetPreference(ctx, tenant, userID, req.Channel, req.EventType, req.Enabled)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, p)
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "notification not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "a conflicting record already exists")
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
