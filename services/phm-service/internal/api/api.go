// Package api exposes the PHM service HTTP endpoints (API Blueprint section 2.5).
package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/phm-service/internal/domain"
	"github.com/siberindo/cti/services/phm-service/internal/service"
	"github.com/siberindo/cti/services/phm-service/internal/store"
)

// Handler holds the PHM endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the PHM routes onto mux. Every route requires a valid token plus
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

	mux.Handle("GET /v1/phm/findings", read(h.listFindings))
	mux.Handle("POST /v1/phm/findings", create(h.createFinding))
	mux.Handle("GET /v1/phm/findings/{id}", read(h.getFinding))
	mux.Handle("PATCH /v1/phm/findings/{id}/status", update(h.updateStatus))
	mux.Handle("POST /v1/phm/findings/{id}/severity-override", update(h.overrideSeverity))
	mux.Handle("POST /v1/phm/findings/{id}/suppress", update(h.suppress))
	mux.Handle("POST /v1/phm/findings/{id}/escalate", update(h.escalate))
	mux.Handle("POST /v1/phm/findings/{id}/promote-urgency", update(h.promoteUrgency))
	mux.Handle("GET /v1/phm/findings/{id}/indicators", read(h.listIndicators))
	mux.Handle("POST /v1/phm/findings/{id}/indicators", update(h.addIndicator))
	mux.Handle("GET /v1/phm/findings/{id}/certificates", read(h.listCertificates))
	mux.Handle("POST /v1/phm/findings/{id}/certificates", update(h.addCertificate))
	mux.Handle("GET /v1/phm/findings/{id}/evidence", read(h.listEvidence))
	mux.Handle("POST /v1/phm/findings/{id}/evidence", update(h.addEvidence))
	mux.Handle("GET /v1/phm/campaigns", read(h.listCampaigns))
	mux.Handle("POST /v1/phm/campaigns", create(h.createCampaign))
	mux.Handle("GET /v1/phm/sources", read(h.listSources))
	mux.Handle("POST /v1/phm/sources", create(h.createSource))
}

func (h *Handler) listFindings(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.FindingFilter{
		Status:      q.Get("status"),
		FindingType: q.Get("finding_type"),
		Severity:    q.Get("severity"),
		CampaignID:  q.Get("campaign_id"),
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
	FindingType         string   `json:"finding_type"`
	Title               string   `json:"title"`
	Severity            string   `json:"severity"`
	ConfidenceScore     float64  `json:"confidence_score"`
	PhishingURLDefanged string   `json:"phishing_url_defanged"`
	HostingIP           *string  `json:"hosting_ip"`
	Registrar           *string  `json:"registrar"`
	CampaignID          *string  `json:"campaign_id"`
	SourceID            *string  `json:"source_id"`
	DedupKey            string   `json:"dedup_key"`
	ContentFingerprint  *string  `json:"content_fingerprint"`
	AssetIDs            []string `json:"asset_ids"`
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
		ConfidenceScore: req.ConfidenceScore, PhishingURLDefanged: req.PhishingURLDefanged,
		HostingIP: req.HostingIP, Registrar: req.Registrar, CampaignID: req.CampaignID,
		SourceID: req.SourceID, DedupKey: req.DedupKey, ContentFingerprint: req.ContentFingerprint,
		AssetIDs: req.AssetIDs,
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

func (h *Handler) promoteUrgency(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	f, err := h.svc.PromoteUrgency(ctx, tenant, r.PathValue("id"), auth.ActorID(r.Context()))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, f)
}

func (h *Handler) listIndicators(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	ind, err := h.svc.ListIndicators(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if ind == nil {
		ind = []domain.Indicator{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, ind)
}

func (h *Handler) addIndicator(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		IndicatorType string   `json:"indicator_type"`
		Value         string   `json:"value"`
		TLPMarking    string   `json:"tlp_marking"`
		Confidence    *float64 `json:"confidence"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	ind, err := h.svc.AddIndicator(ctx, tenant, r.PathValue("id"), service.AddIndicatorInput{
		IndicatorType: req.IndicatorType, Value: req.Value, TLPMarking: req.TLPMarking,
		Confidence: req.Confidence,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, ind)
}

func (h *Handler) listCertificates(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	certs, err := h.svc.ListCertificates(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if certs == nil {
		certs = []domain.SSLCertificate{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, certs)
}

func (h *Handler) addCertificate(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		SerialNumber      string     `json:"serial_number"`
		Issuer            *string    `json:"issuer"`
		Subject           *string    `json:"subject"`
		SANEntries        []string   `json:"san_entries"`
		NotBefore         *time.Time `json:"not_before"`
		NotAfter          *time.Time `json:"not_after"`
		FingerprintSHA256 *string    `json:"fingerprint_sha256"`
		RawCertRef        *string    `json:"raw_cert_ref"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	cert, err := h.svc.AddCertificate(ctx, tenant, r.PathValue("id"), service.AddCertificateInput{
		SerialNumber: req.SerialNumber, Issuer: req.Issuer, Subject: req.Subject,
		SANEntries: req.SANEntries, NotBefore: req.NotBefore, NotAfter: req.NotAfter,
		FingerprintSHA256: req.FingerprintSHA256, RawCertRef: req.RawCertRef,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, cert)
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
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	e, err := h.svc.AddEvidence(ctx, tenant, r.PathValue("id"), service.AddEvidenceInput{
		EvidenceType: req.EvidenceType, ContentHash: req.ContentHash,
		StorageRef: req.StorageRef, Metadata: req.Metadata,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, e)
}

func (h *Handler) listCampaigns(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	camps, err := h.svc.ListCampaigns(r.Context(), tenant)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if camps == nil {
		camps = []domain.Campaign{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, camps)
}

func (h *Handler) createCampaign(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	camp, err := h.svc.CreateCampaign(ctx, tenant, req.Name, req.Description)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, camp)
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
