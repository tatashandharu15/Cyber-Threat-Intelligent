// Package api exposes the Collection Adapter Manager HTTP endpoints under
// /v1/collection/adapters. Every route validates the platform JWT, enforces an
// adapter:* permission, and runs the store in the acting user's context.
package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/domain"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/service"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/store"
)

// Handler holds the Collection Adapter Manager endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the adapter routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("adapter:read"))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("adapter:manage"))
	}

	mux.Handle("GET /v1/collection/adapters", read(h.listAdapters))
	mux.Handle("POST /v1/collection/adapters", manage(h.createAdapter))
	mux.Handle("GET /v1/collection/adapters/{id}", read(h.getAdapter))
	mux.Handle("PATCH /v1/collection/adapters/{id}", manage(h.updateAdapter))
	mux.Handle("POST /v1/collection/adapters/{id}/pause", manage(h.pause))
	mux.Handle("POST /v1/collection/adapters/{id}/resume", manage(h.resume))
	mux.Handle("POST /v1/collection/adapters/{id}/retire", manage(h.retire))
	mux.Handle("POST /v1/collection/adapters/{id}/trigger", manage(h.trigger))
	mux.Handle("GET /v1/collection/adapters/{id}/runs", read(h.listRuns))
}

func (h *Handler) listAdapters(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	adapters, err := h.svc.ListAdapters(r.Context(), tenant, domain.AdapterFilter{
		Module: q.Get("module"), Status: q.Get("status"),
		Limit: atoiDefault(q.Get("limit"), 50), Offset: atoiDefault(q.Get("offset"), 0),
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if adapters == nil {
		adapters = []domain.Adapter{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, adapters)
}

type createAdapterRequest struct {
	Module       string  `json:"module"`
	AdapterType  string  `json:"adapter_type"`
	Name         string  `json:"name"`
	ScheduleCron *string `json:"schedule_cron"`
	ConfigRef    *string `json:"config_ref"`
}

func (h *Handler) createAdapter(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createAdapterRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	adapter, err := h.svc.CreateAdapter(ctx, tenant, service.CreateAdapterInput{
		Module: req.Module, AdapterType: req.AdapterType, Name: req.Name,
		ScheduleCron: req.ScheduleCron, ConfigRef: req.ConfigRef,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, adapter)
}

func (h *Handler) getAdapter(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	a, err := h.svc.GetAdapter(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) updateAdapter(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		ScheduleCron *string `json:"schedule_cron"`
		ConfigRef    *string `json:"config_ref"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.UpdateAdapter(ctx, tenant, r.PathValue("id"), req.ScheduleCron, req.ConfigRef); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) pause(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, h.svc.Pause, "paused")
}

func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, h.svc.Resume, "active")
}

func (h *Handler) retire(w http.ResponseWriter, r *http.Request) {
	h.lifecycle(w, r, h.svc.Retire, "retired")
}

// lifecycleFunc is the shared signature of the pause/resume/retire service methods.
type lifecycleFunc func(ctx context.Context, tenantID, id string) error

// lifecycle is the shared body for pause/resume/retire: it sets the actor context,
// invokes fn, and reports the resulting status.
func (h *Handler) lifecycle(w http.ResponseWriter, r *http.Request, fn lifecycleFunc, status string) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := fn(ctx, tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": status})
}

func (h *Handler) trigger(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.Trigger(ctx, tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusAccepted, map[string]string{"status": "triggered"})
}

func (h *Handler) listRuns(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	runs, err := h.svc.ListRuns(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if runs == nil {
		runs = []domain.RunEvent{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, runs)
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "an adapter with that name already exists for this module")
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "adapter not found")
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
