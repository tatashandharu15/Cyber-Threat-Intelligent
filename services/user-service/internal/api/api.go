// Package api exposes the User service HTTP endpoints. Every route is protected by
// the JWT middleware and a fine-grained permission check; the tenant is taken from
// the verified claim, never from the request body or path.
package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/user-service/internal/service"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// Handler holds the dependencies for the user endpoints.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the user routes onto mux. All routes require a valid bearer token
// and the appropriate permission.
func (h *Handler) Register(mux *http.ServeMux) {
	protected := h.issuer.Middleware()

	mux.Handle("GET /v1/users", httpx.Chain(http.HandlerFunc(h.listUsers), protected, auth.RequirePermission("user:read")))
	mux.Handle("POST /v1/users", httpx.Chain(http.HandlerFunc(h.createUser), protected, auth.RequirePermission("user:create")))
	mux.Handle("GET /v1/users/{id}", httpx.Chain(http.HandlerFunc(h.getUser), protected, auth.RequirePermission("user:read")))
	mux.Handle("PATCH /v1/users/{id}", httpx.Chain(http.HandlerFunc(h.updateUser), protected, auth.RequirePermission("user:update")))
	mux.Handle("POST /v1/users/{id}/roles", httpx.Chain(http.HandlerFunc(h.assignRole), protected, auth.RequirePermission("user:update")))
	mux.Handle("DELETE /v1/users/{id}/roles/{roleId}", httpx.Chain(http.HandlerFunc(h.removeRole), protected, auth.RequirePermission("user:update")))
	mux.Handle("GET /v1/users/{id}/directory-linkage", httpx.Chain(http.HandlerFunc(h.getLinkage), protected, auth.RequirePermission("user:read")))
	mux.Handle("PUT /v1/users/{id}/directory-linkage", httpx.Chain(http.HandlerFunc(h.setLinkage), protected, auth.RequirePermission("user:update")))
}

type createUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Status      string `json:"status"`
}

type updateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Status      *string `json:"status"`
}

type assignRoleRequest struct {
	RoleID string `json:"role_id"`
}

type setLinkageRequest struct {
	DirectoryType string `json:"directory_type"`
	DirectoryRef  string `json:"directory_ref"`
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantID(r.Context())
	limit, offset := pageParams(r)
	users, err := h.svc.ListUsers(r.Context(), tenantID, limit, offset)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, users)
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tenantID := auth.TenantID(r.Context())
	u, err := h.svc.CreateUser(r.Context(), tenantID, req.Email, req.DisplayName, req.Password, req.Status)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, u)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantID(r.Context())
	u, err := h.svc.GetUser(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, u)
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	var req updateUserRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tenantID := auth.TenantID(r.Context())
	u, err := h.svc.UpdateUser(r.Context(), tenantID, r.PathValue("id"), req.DisplayName, req.Status)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, u)
}

func (h *Handler) assignRole(w http.ResponseWriter, r *http.Request) {
	var req assignRoleRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tenantID := auth.TenantID(r.Context())
	if err := h.svc.AssignRole(r.Context(), tenantID, r.PathValue("id"), req.RoleID); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "assigned"})
}

func (h *Handler) removeRole(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantID(r.Context())
	if err := h.svc.RemoveRole(r.Context(), tenantID, r.PathValue("id"), r.PathValue("roleId")); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "removed"})
}

func (h *Handler) getLinkage(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantID(r.Context())
	l, err := h.svc.GetDirectoryLinkage(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, l)
}

func (h *Handler) setLinkage(w http.ResponseWriter, r *http.Request) {
	var req setLinkageRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tenantID := auth.TenantID(r.Context())
	l, err := h.svc.SetDirectoryLinkage(r.Context(), tenantID, r.PathValue("id"), req.DirectoryType, req.DirectoryRef)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, l)
}

// pageParams parses ?limit and ?offset, applying the default and maximum bounds.
func pageParams(r *http.Request) (limit, offset int) {
	limit = defaultLimit
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// mapServiceError translates service/store sentinel errors into the standard API
// error envelope; anything unexpected becomes a generic INTERNAL_ERROR.
func mapServiceError(err error) error {
	switch {
	case errors.Is(err, service.ErrValidation):
		return httpx.NewError(types.ErrValidation, "invalid input")
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "resource not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "resource already exists")
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}
