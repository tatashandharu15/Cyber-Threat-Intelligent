// Package api exposes the Asset service HTTP endpoints. All routes are protected:
// they require a valid bearer token and the relevant asset:* permission. The
// tenant and acting user are taken from the verified JWT claims.
package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/asset-service/internal/domain"
	"github.com/siberindo/cti/services/asset-service/internal/service"
)

// Handler holds the dependencies for the asset endpoints.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the asset routes onto mux. Every route is authenticated and
// guarded by the appropriate permission.
func (h *Handler) Register(mux *http.ServeMux) {
	authn := h.issuer.Middleware()

	protect := func(perm string, fn http.HandlerFunc) http.Handler {
		return httpx.Chain(http.HandlerFunc(fn), authn, auth.RequirePermission(perm))
	}

	mux.Handle("GET /v1/assets", protect("asset:read", h.listAssets))
	mux.Handle("POST /v1/assets", protect("asset:create", h.createAsset))
	mux.Handle("GET /v1/assets/{id}", protect("asset:read", h.getAsset))
	mux.Handle("PATCH /v1/assets/{id}", protect("asset:update", h.updateAsset))
	mux.Handle("POST /v1/assets/{id}/approve", protect("asset:approve", h.approveAsset))
	mux.Handle("POST /v1/assets/{id}/pause", protect("asset:update", h.pauseAsset))
	mux.Handle("POST /v1/assets/{id}/resume", protect("asset:update", h.resumeAsset))
	mux.Handle("DELETE /v1/assets/{id}", protect("asset:delete", h.decommissionAsset))
	mux.Handle("GET /v1/assets/{id}/directory-linkage", protect("asset:read", h.getDirectoryLinkage))
	mux.Handle("PUT /v1/assets/{id}/directory-linkage", protect("asset:update", h.putDirectoryLinkage))
}

func (h *Handler) listAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantID(r.Context())
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	assets, err := h.svc.ListAssets(r.Context(), tenantID, service.ListFilters{
		AssetType:      q.Get("asset_type"),
		Status:         q.Get("status"),
		Criticality:    q.Get("criticality"),
		ApprovalStatus: q.Get("approval_status"),
		Limit:          limit,
		Offset:         offset,
	})
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	if assets == nil {
		assets = []domain.Asset{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, assets)
}

type createAssetRequest struct {
	AssetType   string `json:"asset_type"`
	Value       string `json:"value"`
	DisplayName string `json:"display_name"`
	Criticality string `json:"criticality"`
	Visibility  string `json:"visibility"`
}

func (h *Handler) createAsset(w http.ResponseWriter, r *http.Request) {
	var req createAssetRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(req.AssetType) == "" || strings.TrimSpace(req.Value) == "" {
		httpx.WriteError(w, r, httpx.NewError(types.ErrValidation, "asset_type and value are required"))
		return
	}

	a, err := h.svc.CreateAsset(r.Context(), auth.TenantID(r.Context()), service.CreateInput{
		AssetType:   req.AssetType,
		Value:       req.Value,
		DisplayName: req.DisplayName,
		Criticality: req.Criticality,
		Visibility:  req.Visibility,
	}, auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, a)
}

func (h *Handler) getAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.GetAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

type updateAssetRequest struct {
	DisplayName string `json:"display_name"`
	Criticality string `json:"criticality"`
	Status      string `json:"status"`
}

func (h *Handler) updateAsset(w http.ResponseWriter, r *http.Request) {
	var req updateAssetRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a, err := h.svc.UpdateAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"),
		req.DisplayName, req.Criticality, req.Status)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) approveAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.ApproveAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"), auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) pauseAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.PauseAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) resumeAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.ResumeAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) decommissionAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.DecommissionAsset(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, a)
}

func (h *Handler) getDirectoryLinkage(w http.ResponseWriter, r *http.Request) {
	l, err := h.svc.GetDirectoryLinkage(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, l)
}

type directoryLinkageRequest struct {
	DirectoryType string `json:"directory_type"`
	DirectoryRef  string `json:"directory_ref"`
}

func (h *Handler) putDirectoryLinkage(w http.ResponseWriter, r *http.Request) {
	var req directoryLinkageRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	l, err := h.svc.SetDirectoryLinkage(r.Context(), auth.TenantID(r.Context()), r.PathValue("id"),
		req.DirectoryType, req.DirectoryRef)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, l)
}

// mapServiceError translates service/store sentinel errors into the API error
// envelope. ErrValidation surfaces its message; the approval-gate violation is a
// business-rule violation, while plain input failures are validation errors.
func mapServiceError(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "asset not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "an asset with this value and type already exists")
	case errors.Is(err, service.ErrValidation):
		code := types.ErrValidation
		if strings.Contains(err.Error(), "not pending approval") {
			code = types.ErrBusinessRule
		}
		return httpx.NewError(code, err.Error())
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}
