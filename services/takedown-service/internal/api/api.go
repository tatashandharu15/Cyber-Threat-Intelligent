// Package api exposes the Takedown service HTTP endpoints.
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/takedown-service/internal/domain"
	"github.com/siberindo/cti/services/takedown-service/internal/service"
	"github.com/siberindo/cti/services/takedown-service/internal/store"
)

// Handler holds the Takedown endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Takedown routes onto mux. Every route requires a valid token
// plus the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("takedown:read"))
	}
	create := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("takedown:create"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("takedown:update"))
	}

	mux.Handle("GET /v1/takedowns", read(h.listTakedowns))
	mux.Handle("POST /v1/takedowns", create(h.createTakedown))
	mux.Handle("GET /v1/takedowns/{id}", read(h.getTakedown))
	mux.Handle("POST /v1/takedowns/{id}/submit", update(h.submit))
	mux.Handle("PATCH /v1/takedowns/{id}/status", update(h.updateStatus))
	mux.Handle("GET /v1/takedowns/{id}/events", read(h.listEvents))
}

func (h *Handler) listTakedowns(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.TakedownFilter{
		Status:       q.Get("status"),
		SourceModule: q.Get("source_module"),
		Limit:        atoiDefault(q.Get("limit"), 50),
		Offset:       atoiDefault(q.Get("offset"), 0),
	}
	takedowns, err := h.svc.ListTakedowns(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if takedowns == nil {
		takedowns = []domain.Takedown{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, takedowns)
}

type createTakedownRequest struct {
	SourceModule         string `json:"source_module"`
	SourceFindingID      string `json:"source_finding_id"`
	SubmissionTarget     string `json:"submission_target"`
	SubmissionTargetType string `json:"submission_target_type"`
	EvidencePackageRef   string `json:"evidence_package_ref"`
}

func (h *Handler) createTakedown(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createTakedownRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	td, err := h.svc.CreateTakedown(ctx, tenant, service.CreateTakedownInput{
		SourceModule: req.SourceModule, SourceFindingID: req.SourceFindingID,
		SubmissionTarget: req.SubmissionTarget, SubmissionTargetType: req.SubmissionTargetType,
		EvidencePackageRef: req.EvidencePackageRef,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, td)
}

func (h *Handler) getTakedown(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	td, err := h.svc.GetTakedown(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, td)
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	td, err := h.svc.Submit(ctx, tenant, r.PathValue("id"), auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, td)
}

func (h *Handler) updateStatus(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Status           string `json:"status"`
		OperatorResponse string `json:"operator_response"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	td, err := h.svc.UpdateStatus(ctx, tenant, r.PathValue("id"), req.Status, req.OperatorResponse, auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, td)
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ev, err := h.svc.ListEvents(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if ev == nil {
		ev = []domain.TakedownEvent{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, ev)
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "takedown not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "takedown conflict")
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
