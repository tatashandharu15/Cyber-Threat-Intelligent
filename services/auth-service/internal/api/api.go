// Package api exposes the Auth service HTTP endpoints (API Blueprint section 2.1).
package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/auth-service/internal/domain"
	"github.com/siberindo/cti/services/auth-service/internal/service"
)

// Handler holds the dependencies for the auth endpoints.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the auth routes onto mux. Public routes are open; protected
// routes require a valid bearer token.
func (h *Handler) Register(mux *http.ServeMux) {
	protected := h.issuer.Middleware()

	mux.HandleFunc("POST /v1/auth/login", h.login)
	mux.HandleFunc("POST /v1/auth/refresh", h.refresh)
	mux.Handle("POST /v1/auth/logout", httpx.Chain(http.HandlerFunc(h.logout), protected))
	mux.Handle("GET /v1/auth/me", httpx.Chain(http.HandlerFunc(h.me), protected))

	// Public JWKS endpoint so other services and the API gateway can fetch the
	// RS256 verification key. In HS256 mode this returns an empty key set.
	mux.HandleFunc("GET /.well-known/jwks.json", h.jwks)
}

// jwks serves the issuer's JSON Web Key Set. It requires no authentication.
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	doc, err := h.issuer.JWKS()
	if err != nil {
		httpx.WriteError(w, r, httpx.NewError(types.ErrInternal, "failed to build jwks"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

type loginRequest struct {
	TenantSlug string `json:"tenant_slug"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	MFACode    string `json:"mfa_code"`
}

type tokenResponse struct {
	Token     string       `json:"token"`
	TokenType string       `json:"token_type"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      *domain.User `json:"user"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if req.TenantSlug == "" || req.Email == "" || req.Password == "" {
		httpx.WriteError(w, r, httpx.NewError(types.ErrValidation, "tenant_slug, email and password are required"))
		return
	}

	res, err := h.svc.Login(r.Context(), service.LoginInput{
		TenantSlug: req.TenantSlug,
		Email:      strings.ToLower(strings.TrimSpace(req.Email)),
		Password:   req.Password,
		MFACode:    req.MFACode,
		IP:         clientIP(r),
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		httpx.WriteError(w, r, mapAuthError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, tokenResponse{
		Token: res.Token, TokenType: "Bearer", ExpiresAt: res.ExpiresAt, User: res.User,
	})
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	raw := bearer(r)
	if raw == "" {
		httpx.WriteError(w, r, httpx.NewError(types.ErrUnauthorized, "missing bearer token"))
		return
	}
	res, err := h.svc.Refresh(r.Context(), raw, clientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, mapAuthError(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, tokenResponse{
		Token: res.Token, TokenType: "Bearer", ExpiresAt: res.ExpiresAt, User: res.User,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFrom(r.Context())
	if claims == nil {
		httpx.WriteError(w, r, httpx.NewError(types.ErrUnauthorized, "not authenticated"))
		return
	}
	if err := h.svc.Logout(r.Context(), claims.TenantID, claims.ID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFrom(r.Context())
	if claims == nil {
		httpx.WriteError(w, r, httpx.NewError(types.ErrUnauthorized, "not authenticated"))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{
		"user_id":     claims.Subject,
		"tenant_id":   claims.TenantID,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
		"session_id":  claims.ID,
	})
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		return httpx.NewError(types.ErrUnauthorized, "invalid credentials")
	case errors.Is(err, service.ErrUserInactive):
		return httpx.NewError(types.ErrForbidden, "user account is not active")
	case errors.Is(err, service.ErrMFARequired):
		return &httpx.APIError{Code: types.ErrUnauthorized, Message: "mfa code required", Details: map[string]bool{"mfa_required": true}}
	case errors.Is(err, service.ErrMFAInvalid):
		return httpx.NewError(types.ErrUnauthorized, "invalid mfa code")
	case errors.Is(err, service.ErrSessionInactive):
		return httpx.NewError(types.ErrUnauthorized, "session is no longer active")
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
