// Package api exposes the DWM (Dark Web Monitoring) service HTTP endpoints.
package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/dwm-service/internal/domain"
	"github.com/siberindo/cti/services/dwm-service/internal/service"
	"github.com/siberindo/cti/services/dwm-service/internal/store"
)

// Handler holds the DWM endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the DWM routes onto mux. Every route requires a valid token plus
// the relevant permission.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("finding:read"))
	}
	create := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("finding:create"))
	}
	update := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("finding:update"))
	}

	mux.Handle("GET /v1/dwm/findings", read(h.listFindings))
	mux.Handle("POST /v1/dwm/findings", create(h.createFinding))
	mux.Handle("GET /v1/dwm/findings/{id}", read(h.getFinding))
	mux.Handle("PATCH /v1/dwm/findings/{id}/status", update(h.updateStatus))
	mux.Handle("POST /v1/dwm/findings/{id}/severity-override", update(h.overrideSeverity))
	mux.Handle("POST /v1/dwm/findings/{id}/suppress", update(h.suppress))
	mux.Handle("POST /v1/dwm/findings/{id}/escalate", update(h.escalate))
	mux.Handle("POST /v1/dwm/findings/{id}/enrich", update(h.enrich))
	mux.Handle("POST /v1/dwm/findings/{id}/threat-actors", update(h.linkThreatActor))
	mux.Handle("GET /v1/dwm/findings/{id}/evidence", read(h.listEvidence))
	mux.Handle("POST /v1/dwm/findings/{id}/evidence", update(h.addEvidence))
	mux.Handle("GET /v1/dwm/threat-actors", read(h.listThreatActors))
	mux.Handle("POST /v1/dwm/threat-actors", create(h.createThreatActor))
}

func (h *Handler) listFindings(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.FindingFilter{
		Status:      q.Get("status"),
		FindingType: q.Get("finding_type"),
		Severity:    q.Get("severity"),
		Limit:       atoiDefault(q.Get("limit"), 50),
		Offset:      atoiDefault(q.Get("offset"), 0),
	}
	findings, err := h.svc.ListFindings(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if findings == nil {
		findings = []domain.Finding{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, findings)
}

type createFindingRequest struct {
	FindingType        string     `json:"finding_type"`
	Title              string     `json:"title"`
	Severity           string     `json:"severity"`
	ConfidenceScore    float64    `json:"confidence_score"`
	SourceTierID       *string    `json:"source_tier_id"`
	DedupKey           string     `json:"dedup_key"`
	ContentExcerpt     *string    `json:"content_excerpt"`
	ContentURLDefanged *string    `json:"content_url_defanged"`
	ObservedAt         *time.Time `json:"observed_at"`
	AssetIDs           []string   `json:"asset_ids"`
}

func (h *Handler) createFinding(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createFindingRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	f, err := h.svc.CreateFinding(ctx, tenant, service.CreateFindingInput{
		FindingType: req.FindingType, Title: req.Title, Severity: req.Severity,
		ConfidenceScore: req.ConfidenceScore, SourceTierID: req.SourceTierID, DedupKey: req.DedupKey,
		ContentExcerpt: req.ContentExcerpt, ContentURLDefanged: req.ContentURLDefanged,
		ObservedAt: req.ObservedAt, AssetIDs: req.AssetIDs,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, f)
}

func (h *Handler) getFinding(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	f, err := h.svc.GetFinding(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, f)
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

func (h *Handler) overrideSeverity(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Severity      string `json:"severity"`
		Justification string `json:"justification"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.OverrideSeverity(ctx, tenant, r.PathValue("id"), req.Severity, req.Justification); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"severity": req.Severity})
}

func (h *Handler) suppress(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Justification string `json:"justification"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	if err := h.svc.Suppress(ctx, tenant, r.PathValue("id"), req.Justification); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "suppressed"})
}

func (h *Handler) escalate(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	f, err := h.svc.Escalate(ctx, tenant, r.PathValue("id"), auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, f)
}

func (h *Handler) enrich(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		TacticsObserved    []string `json:"tactics_observed"`
		AffectedAssetScope *string  `json:"affected_asset_scope"`
		ResponseIndicators *string  `json:"response_indicators"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	e, err := h.svc.AddEnrichment(ctx, tenant, r.PathValue("id"), service.AddEnrichmentInput{
		TacticsObserved: req.TacticsObserved, AffectedAssetScope: req.AffectedAssetScope,
		ResponseIndicators: req.ResponseIndicators,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, e)
}

func (h *Handler) linkThreatActor(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		ThreatActorID string `json:"threat_actor_id"`
		Justification string `json:"justification"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	actorID := auth.ActorID(r.Context())
	if err := h.svc.LinkThreatActor(ctx, tenant, r.PathValue("id"), req.ThreatActorID, actorID, req.Justification); err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, map[string]string{
		"finding_id": r.PathValue("id"), "threat_actor_id": req.ThreatActorID,
	})
}

func (h *Handler) listEvidence(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ev, err := h.svc.ListEvidence(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if ev == nil {
		ev = []domain.Evidence{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, ev)
}

func (h *Handler) addEvidence(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		EvidenceType string  `json:"evidence_type"`
		ContentHash  string  `json:"content_hash"`
		StorageRef   *string `json:"storage_ref"`
		Metadata     []byte  `json:"metadata"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := h.svc.AddEvidence(r.Context(), tenant, r.PathValue("id"), service.AddEvidenceInput{
		EvidenceType: req.EvidenceType, ContentHash: req.ContentHash,
		StorageRef: req.StorageRef, Metadata: req.Metadata,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, e)
}

func (h *Handler) listThreatActors(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	actors, err := h.svc.ListThreatActors(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if actors == nil {
		actors = []domain.ThreatActorProfile{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, actors)
}

func (h *Handler) createThreatActor(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Codename    string   `json:"codename"`
		Description *string  `json:"description"`
		Aliases     []string `json:"aliases"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	a, err := h.svc.CreateThreatActor(ctx, tenant, req.Codename, req.Description, req.Aliases)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, a)
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "resource not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "a resource with these identifiers already exists")
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
