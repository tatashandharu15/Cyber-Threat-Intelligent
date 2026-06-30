// Package api exposes the Role service HTTP endpoints: RBAC role CRUD, the global
// permission catalog, role-permission grants, and user-role assignments. Every
// route requires a valid bearer token plus the relevant permission.
package api

import (
	"errors"
	"net/http"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/role-service/internal/domain"
	"github.com/siberindo/cti/services/role-service/internal/service"
)

// Handler holds the Role endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Role routes onto mux. Reads require role:read; mutations
// require role:manage.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("role:read"))
	}
	manage := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("role:manage"))
	}

	mux.Handle("GET /v1/roles", read(h.listRoles))
	mux.Handle("POST /v1/roles", manage(h.createRole))
	mux.Handle("GET /v1/roles/{id}", read(h.getRole))
	mux.Handle("PATCH /v1/roles/{id}", manage(h.updateRole))
	mux.Handle("DELETE /v1/roles/{id}", manage(h.deleteRole))
	mux.Handle("GET /v1/roles/{id}/permissions", read(h.listRolePermissions))
	mux.Handle("POST /v1/roles/{id}/permissions", manage(h.grantPermission))
	mux.Handle("DELETE /v1/roles/{id}/permissions/{permissionId}", manage(h.revokePermission))

	mux.Handle("GET /v1/permissions", read(h.listPermissions))

	mux.Handle("GET /v1/users/{userId}/roles", read(h.listUserRoles))
	mux.Handle("POST /v1/users/{userId}/roles", manage(h.assignUserRole))
	mux.Handle("DELETE /v1/users/{userId}/roles/{roleId}", manage(h.removeUserRole))
}

func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	roles, err := h.svc.ListRoles(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, roles)
}

type createRoleRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

func (h *Handler) createRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createRoleRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	role, err := h.svc.CreateRole(r.Context(), tenant, service.CreateRoleInput{
		Name: req.Name, Description: req.Description,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, role)
}

func (h *Handler) getRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	role, err := h.svc.GetRole(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, role)
}

type updateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (h *Handler) updateRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req updateRoleRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	role, err := h.svc.UpdateRole(r.Context(), tenant, r.PathValue("id"), service.UpdateRoleInput{
		Name: req.Name, Description: req.Description,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, role)
}

func (h *Handler) deleteRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	if err := h.svc.DeleteRole(r.Context(), tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) listRolePermissions(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	perms, err := h.svc.ListRolePermissions(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if perms == nil {
		perms = []domain.Permission{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, perms)
}

type grantPermissionRequest struct {
	PermissionID string `json:"permission_id"`
}

func (h *Handler) grantPermission(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req grantPermissionRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.svc.GrantPermission(r.Context(), tenant, r.PathValue("id"), req.PermissionID); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "granted"})
}

func (h *Handler) revokePermission(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	if err := h.svc.RevokePermission(r.Context(), tenant, r.PathValue("id"), r.PathValue("permissionId")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *Handler) listPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.svc.ListPermissions(r.Context())
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if perms == nil {
		perms = []domain.Permission{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, perms)
}

func (h *Handler) listUserRoles(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	roles, err := h.svc.ListUserRoles(r.Context(), tenant, r.PathValue("userId"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, roles)
}

type assignUserRoleRequest struct {
	RoleID string `json:"role_id"`
}

func (h *Handler) assignUserRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req assignUserRoleRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.svc.AssignUserRole(r.Context(), tenant, r.PathValue("userId"), req.RoleID); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, map[string]string{"status": "assigned"})
}

func (h *Handler) removeUserRole(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	if err := h.svc.RemoveUserRole(r.Context(), tenant, r.PathValue("userId"), r.PathValue("roleId")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "removed"})
}

// mapErr translates service/store errors into the standard API error envelope.
func mapErr(err error) error {
	switch {
	case errors.Is(err, service.ErrImmutableSystemRole):
		return httpx.NewError(types.ErrBusinessRule, "system roles are immutable")
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "resource not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "a role with this name already exists in the tenant")
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}
