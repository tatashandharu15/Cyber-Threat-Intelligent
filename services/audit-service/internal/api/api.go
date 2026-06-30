// Package api exposes the Audit Log service HTTP endpoints. Every route requires a
// valid JWT plus the relevant audit:* permission.
package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/audit-service/internal/domain"
	"github.com/siberindo/cti/services/audit-service/internal/service"
)

// Handler holds the Audit Log endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Audit Log routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("audit:read"))
	}
	write := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("audit:write"))
	}

	mux.Handle("POST /v1/audit-logs", write(h.create))
	mux.Handle("GET /v1/audit-logs", read(h.list))
	mux.Handle("GET /v1/audit-logs/{id}", read(h.get))
	mux.Handle("GET /v1/audit-logs/{id}/verify", read(h.verify))
}

type createRequest struct {
	EventType    string          `json:"event_type"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id"`
	Action       string          `json:"action"`
	Outcome      string          `json:"outcome"`
	ActorType    string          `json:"actor_type"`
	EventPayload json.RawMessage `json:"event_payload"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in := service.RecordInput{
		ActorID:      auth.ActorID(r.Context()),
		ActorType:    req.ActorType,
		EventType:    req.EventType,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Action:       req.Action,
		Outcome:      req.Outcome,
		IP:           clientIP(r),
		UserAgent:    userAgent(r),
		RequestID:    requestID(r),
		Payload:      []byte(req.EventPayload),
	}
	e, err := h.svc.Record(r.Context(), tenant, in)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, e)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.AuditFilter{
		EventType:    q.Get("event_type"),
		ResourceType: q.Get("resource_type"),
		ActorID:      q.Get("actor_id"),
		Outcome:      q.Get("outcome"),
		Limit:        atoiDefault(q.Get("limit"), 50),
		Offset:       atoiDefault(q.Get("offset"), 0),
	}
	events, err := h.svc.List(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if events == nil {
		events = []domain.AuditEvent{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, events)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	e, err := h.svc.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, e)
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	id := r.PathValue("id")
	valid, err := h.svc.Verify(r.Context(), tenant, id)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]any{"id": id, "valid": valid})
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "audit event not found")
	default:
		return httpx.NewError(types.ErrInternal, "internal server error")
	}
}

// clientIP returns the originating client IP, preferring the first X-Forwarded-For
// hop (set by Kong/load balancers) and falling back to the request RemoteAddr.
func clientIP(r *http.Request) *string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip != "" {
			return &ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return &host
	}
	if r.RemoteAddr != "" {
		ra := r.RemoteAddr
		return &ra
	}
	return nil
}

func userAgent(r *http.Request) *string {
	if ua := r.UserAgent(); ua != "" {
		return &ua
	}
	return nil
}

func requestID(r *http.Request) *string {
	if id := httpx.RequestID(r.Context()); id != "" {
		return &id
	}
	return nil
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
