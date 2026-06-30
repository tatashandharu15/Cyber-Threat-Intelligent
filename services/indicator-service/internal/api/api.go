// Package api exposes the Indicator Management service HTTP endpoints.
package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/indicator-service/internal/domain"
	"github.com/siberindo/cti/services/indicator-service/internal/service"
	"github.com/siberindo/cti/services/indicator-service/internal/store"
)

// Handler holds the Indicator endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Indicator routes onto mux. Every route requires a valid token
// plus the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("indicator:read"))
	}
	create := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("indicator:create"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("indicator:update"))
	}

	mux.Handle("GET /v1/indicators", read(h.listIndicators))
	mux.Handle("POST /v1/indicators", create(h.createIndicator))
	mux.Handle("GET /v1/indicators/{id}", read(h.getIndicator))
	mux.Handle("PATCH /v1/indicators/{id}", update(h.updateIndicator))
	mux.Handle("DELETE /v1/indicators/{id}", update(h.deleteIndicator))
}

func (h *Handler) listIndicators(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.IndicatorFilter{
		IndicatorType: q.Get("indicator_type"),
		TLPMarking:    q.Get("tlp_marking"),
		SourceModule:  q.Get("source_module"),
		Value:         q.Get("value"),
		Limit:         atoiDefault(q.Get("limit"), 50),
		Offset:        atoiDefault(q.Get("offset"), 0),
	}
	indicators, err := h.svc.ListIndicators(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if indicators == nil {
		indicators = []domain.Indicator{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, indicators)
}

type createIndicatorRequest struct {
	IndicatorType   string     `json:"indicator_type"`
	Value           string     `json:"value"`
	TLPMarking      string     `json:"tlp_marking"`
	Confidence      *float64   `json:"confidence"`
	SourceModule    *string    `json:"source_module"`
	SourceFindingID *string    `json:"source_finding_id"`
	Tags            []string   `json:"tags"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

func (h *Handler) createIndicator(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createIndicatorRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	ind, err := h.svc.RegisterIndicator(ctx, tenant, service.RegisterIndicatorInput{
		IndicatorType: req.IndicatorType, Value: req.Value, TLPMarking: req.TLPMarking,
		Confidence: req.Confidence, SourceModule: req.SourceModule,
		SourceFindingID: req.SourceFindingID, Tags: req.Tags, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, ind)
}

func (h *Handler) getIndicator(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ind, err := h.svc.GetIndicator(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, ind)
}

type updateIndicatorRequest struct {
	TLPMarking *string    `json:"tlp_marking"`
	Confidence *float64   `json:"confidence"`
	Tags       *[]string  `json:"tags"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

func (h *Handler) updateIndicator(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req updateIndicatorRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	ind, err := h.svc.UpdateIndicator(ctx, tenant, r.PathValue("id"), service.UpdateIndicatorInput{
		TLPMarking: req.TLPMarking, Confidence: req.Confidence,
		Tags: req.Tags, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, ind)
}

func (h *Handler) deleteIndicator(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.DeleteIndicator(ctx, tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "indicator not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "an indicator with this type and value already exists")
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
