// Package api exposes the BRM service HTTP endpoints (API Blueprint section 2.7).
package api

import (
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/brm-service/internal/domain"
	"github.com/siberindo/cti/services/brm-service/internal/service"
	"github.com/siberindo/cti/services/brm-service/internal/store"
)

// Handler holds the BRM endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the BRM routes onto mux. Every route requires a valid token plus
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

	mux.Handle("GET /v1/brm/findings", read(h.listFindings))
	mux.Handle("POST /v1/brm/findings", create(h.createFinding))
	mux.Handle("GET /v1/brm/findings/{id}", read(h.getFinding))
	mux.Handle("PATCH /v1/brm/findings/{id}/status", update(h.updateStatus))
	mux.Handle("POST /v1/brm/findings/{id}/severity-override", update(h.overrideSeverity))
	mux.Handle("POST /v1/brm/findings/{id}/suppress", update(h.suppress))
	mux.Handle("POST /v1/brm/findings/{id}/escalate", update(h.escalate))
	mux.Handle("POST /v1/brm/findings/{id}/takedown", update(h.takedown))
	mux.Handle("GET /v1/brm/findings/{id}/evidence", read(h.listEvidence))
	mux.Handle("POST /v1/brm/findings/{id}/evidence", update(h.addEvidence))
	mux.Handle("GET /v1/brm/sources", read(h.listSources))
	mux.Handle("POST /v1/brm/sources", create(h.createSource))
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
	FindingType                string   `json:"finding_type"`
	Title                      string   `json:"title"`
	Severity                   string   `json:"severity"`
	ConfidenceScore            float64  `json:"confidence_score"`
	SimilarityScore            *float64 `json:"similarity_score"`
	SimilarityAlgorithmVersion *string  `json:"similarity_algorithm_version"`
	CandidateValue             string   `json:"candidate_value"`
	SourceID                   *string  `json:"source_id"`
	DedupKey                   string   `json:"dedup_key"`
	SocialPlatformID           *string  `json:"social_platform_id"`
	SocialAccountHandle        *string  `json:"social_account_handle"`
	SocialProfileURL           *string  `json:"social_profile_url"`
	AppStoreID                 *string  `json:"app_store_id"`
	AppPlatform                *string  `json:"app_platform"`
	AppListingURL              *string  `json:"app_listing_url"`
	AppPackageID               *string  `json:"app_package_id"`
	AssetIDs                   []string `json:"asset_ids"`
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
		ConfidenceScore: req.ConfidenceScore, SimilarityScore: req.SimilarityScore,
		SimilarityAlgorithmVersion: req.SimilarityAlgorithmVersion, CandidateValue: req.CandidateValue,
		SourceID: req.SourceID, DedupKey: req.DedupKey,
		SocialPlatformID: req.SocialPlatformID, SocialAccountHandle: req.SocialAccountHandle,
		SocialProfileURL: req.SocialProfileURL, AppStoreID: req.AppStoreID, AppPlatform: req.AppPlatform,
		AppListingURL: req.AppListingURL, AppPackageID: req.AppPackageID, AssetIDs: req.AssetIDs,
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

func (h *Handler) takedown(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	f, err := h.svc.InitiateTakedown(ctx, tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, f)
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
		StorageRef   *string `json:"storage_ref"`
		ContentHash  string  `json:"content_hash"`
		Metadata     []byte  `json:"metadata"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := h.svc.AddEvidence(r.Context(), tenant, r.PathValue("id"), service.AddEvidenceInput{
		EvidenceType: req.EvidenceType, StorageRef: req.StorageRef, ContentHash: req.ContentHash,
		Metadata: req.Metadata,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, e)
}

func (h *Handler) listSources(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	srcs, err := h.svc.ListSources(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if srcs == nil {
		srcs = []domain.CollectionSource{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, srcs)
}

func (h *Handler) createSource(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		SourceType  string `json:"source_type"`
		DisplayName string `json:"display_name"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	src, err := h.svc.CreateSource(ctx, tenant, req.SourceType, req.DisplayName)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, src)
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "finding not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "a finding with this dedup_key already exists")
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
