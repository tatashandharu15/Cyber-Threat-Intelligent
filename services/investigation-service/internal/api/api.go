// Package api exposes the Investigation service HTTP endpoints.
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/investigation-service/internal/domain"
	"github.com/siberindo/cti/services/investigation-service/internal/service"
	"github.com/siberindo/cti/services/investigation-service/internal/store"
)

// Handler holds the Investigation endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Investigation routes onto mux. Every route requires a valid
// token plus the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("investigation:read"))
	}
	create := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("investigation:create"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("investigation:update"))
	}

	mux.Handle("GET /v1/investigations", read(h.listInvestigations))
	mux.Handle("POST /v1/investigations", create(h.createInvestigation))
	mux.Handle("GET /v1/investigations/inbox", read(h.listInbox))
	mux.Handle("GET /v1/investigations/{id}", read(h.getInvestigation))
	mux.Handle("PATCH /v1/investigations/{id}/status", update(h.updateStatus))
	mux.Handle("POST /v1/investigations/{id}/assign", update(h.assign))
	mux.Handle("POST /v1/investigations/{id}/notes", update(h.addNote))
	mux.Handle("POST /v1/investigations/{id}/findings", update(h.linkFinding))
	mux.Handle("GET /v1/investigations/{id}/timeline", read(h.listTimeline))
	mux.Handle("POST /v1/investigations/{id}/close", update(h.close))
}

func (h *Handler) listInvestigations(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.InvestigationFilter{
		Status:     q.Get("status"),
		Priority:   q.Get("priority"),
		AssignedTo: q.Get("assigned_to"),
		Limit:      atoiDefault(q.Get("limit"), 50),
		Offset:     atoiDefault(q.Get("offset"), 0),
	}
	invs, err := h.svc.ListInvestigations(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if invs == nil {
		invs = []domain.Investigation{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, invs)
}

type createInvestigationRequest struct {
	Title       string  `json:"title"`
	Description *string `json:"description"`
	Priority    string  `json:"priority"`
}

func (h *Handler) createInvestigation(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createInvestigationRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	inv, err := h.svc.CreateInvestigation(ctx, tenant, service.CreateInvestigationInput{
		Title: req.Title, Description: req.Description, Priority: req.Priority,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, inv)
}

func (h *Handler) listInbox(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	inbox, err := h.svc.ListInbox(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if inbox == nil {
		inbox = []domain.InboxAlert{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, inbox)
}

// investigationDetail bundles an investigation with its linked findings and timeline.
type investigationDetail struct {
	domain.Investigation
	LinkedFindings []domain.LinkedFinding `json:"linked_findings"`
	Timeline       []domain.TimelineEntry `json:"timeline"`
}

func (h *Handler) getInvestigation(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	id := r.PathValue("id")
	inv, err := h.svc.GetInvestigation(r.Context(), tenant, id)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	findings, err := h.svc.ListLinkedFindings(r.Context(), tenant, id)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if findings == nil {
		findings = []domain.LinkedFinding{}
	}
	timeline, err := h.svc.ListTimeline(r.Context(), tenant, id)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if timeline == nil {
		timeline = []domain.TimelineEntry{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, investigationDetail{
		Investigation: *inv, LinkedFindings: findings, Timeline: timeline,
	})
}

func (h *Handler) updateStatus(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Status string `json:"status"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.UpdateStatus(ctx, tenant, r.PathValue("id"), req.Status); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": req.Status})
}

func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		AssignedTo string `json:"assigned_to"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.Assign(ctx, tenant, r.PathValue("id"), req.AssignedTo); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"assigned_to": req.AssignedTo})
}

func (h *Handler) addNote(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Note string `json:"note"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.AddNote(ctx, tenant, r.PathValue("id"), req.Note); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, map[string]string{"status": "note added"})
}

func (h *Handler) linkFinding(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		SourceModule    string  `json:"source_module"`
		SourceFindingID string  `json:"source_finding_id"`
		Notes           *string `json:"notes"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.LinkFinding(ctx, tenant, r.PathValue("id"), service.LinkFindingInput{
		SourceModule: req.SourceModule, SourceFindingID: req.SourceFindingID, Notes: req.Notes,
	}); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, map[string]string{"status": "finding linked"})
}

func (h *Handler) listTimeline(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	timeline, err := h.svc.ListTimeline(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if timeline == nil {
		timeline = []domain.TimelineEntry{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, timeline)
}

func (h *Handler) close(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.Close(ctx, tenant, r.PathValue("id")); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "closed"})
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "investigation not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "this finding is already linked to the investigation")
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
