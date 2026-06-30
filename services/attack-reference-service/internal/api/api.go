// Package api exposes the ATT&CK Reference service HTTP endpoints. These are
// global reads over reference data: every route requires a valid JWT plus the
// relevant permission, but no tenant context is established (the catalog is shared
// across all tenants), so handlers never call WithTenant.
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/attack-reference-service/internal/domain"
	"github.com/siberindo/cti/services/attack-reference-service/internal/service"
)

// Handler holds the ATT&CK reference endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the ATT&CK reference routes onto mux. Every route requires a
// valid token plus the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("attack:read"))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("attack:manage"))
	}

	mux.Handle("GET /v1/attack-reference/techniques", read(h.listTechniques))
	mux.Handle("GET /v1/attack-reference/techniques/{techniqueId}", read(h.getTechnique))
	mux.Handle("POST /v1/attack-reference/sync", manage(h.sync))
}

func (h *Handler) listTechniques(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fil := domain.TechniqueFilter{
		Tactic: q.Get("tactic"),
		Search: q.Get("search"),
		Limit:  atoiDefault(q.Get("limit"), 100),
		Offset: atoiDefault(q.Get("offset"), 0),
	}
	techniques, err := h.svc.ListTechniques(r.Context(), fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if techniques == nil {
		techniques = []domain.Technique{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, techniques)
}

func (h *Handler) getTechnique(w http.ResponseWriter, r *http.Request) {
	t, err := h.svc.GetTechnique(r.Context(), r.PathValue("techniqueId"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, t)
}

type syncRequest struct {
	Techniques []domain.Technique `json:"techniques"`
}

// sync upserts a batch of techniques supplied in the request body. When the body
// is empty or absent, it seeds the built-in default technique set instead.
func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	var req syncRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}

	var (
		inserted int
		err      error
	)
	if len(req.Techniques) == 0 {
		inserted, err = h.svc.SeedDefaults(r.Context())
	} else {
		inserted, err = h.svc.Sync(r.Context(), req.Techniques)
	}
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]int{"inserted": inserted})
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "technique not found")
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
