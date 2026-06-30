// Package api exposes the Reporting service HTTP endpoints. Responses use the
// shared {data,meta} / {error,meta} envelope; every route requires a valid bearer
// token plus the relevant permission.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/services/reporting-service/internal/domain"
	"github.com/siberindo/cti/services/reporting-service/internal/service"
	"github.com/siberindo/cti/services/reporting-service/internal/store"
)

// Handler holds the Reporting endpoint dependencies.
type Handler struct {
	svc    *service.Service
	issuer *auth.Issuer
}

// New returns a Handler.
func New(svc *service.Service, issuer *auth.Issuer) *Handler {
	return &Handler{svc: svc, issuer: issuer}
}

// Register wires the Reporting routes onto mux.
func (h *Handler) Register(mux *http.ServeMux) {
	read := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("report:read"))
	}
	create := func(fn http.HandlerFunc) http.Handler {
		return httpx.Chain(fn, h.issuer.Middleware(), auth.RequirePermission("report:create"))
	}

	mux.Handle("GET /v1/reports", read(h.listReports))
	mux.Handle("POST /v1/reports", create(h.createReport))
	mux.Handle("GET /v1/reports/{id}", read(h.getReport))
	mux.Handle("GET /v1/reports/{id}/download", read(h.downloadReport))
}

func (h *Handler) listReports(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	q := r.URL.Query()
	fil := domain.ReportFilter{
		ReportType: q.Get("report_type"),
		Status:     q.Get("status"),
		Limit:      atoiDefault(q.Get("limit"), 50),
		Offset:     atoiDefault(q.Get("offset"), 0),
	}
	reports, err := h.svc.ListReports(r.Context(), tenant, fil)
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if reports == nil {
		reports = []domain.Report{}
	}
	httpx.WriteJSON(w, r, http.StatusOK, reports)
}

type createReportRequest struct {
	ReportType   string          `json:"report_type"`
	Title        string          `json:"title"`
	OutputFormat string          `json:"output_format"`
	Parameters   json.RawMessage `json:"parameters"`
}

func (h *Handler) createReport(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	var req createReportRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := store.WithActor(r.Context(), auth.ActorID(r.Context()))
	var requestedBy *string
	if actor := auth.ActorID(r.Context()); actor != "" {
		requestedBy = &actor
	}
	rep, err := h.svc.RequestReport(ctx, tenant, service.RequestReportInput{
		ReportType: req.ReportType, Title: req.Title, Format: req.OutputFormat,
		Parameters: req.Parameters, RequestedBy: requestedBy,
	})
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusCreated, rep)
}

func (h *Handler) getReport(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	rep, err := h.svc.GetReport(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, rep)
}

// downloadReport returns the report's output reference if it is complete, or a 409
// CONFLICT if the report has not finished generating.
func (h *Handler) downloadReport(w http.ResponseWriter, r *http.Request) {
	tenant := auth.TenantID(r.Context())
	rep, err := h.svc.GetReport(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, mapErr(err))
		return
	}
	if rep.Status != "complete" || rep.OutputRef == nil {
		httpx.WriteError(w, r, httpx.NewError(types.ErrConflict, "report is not ready for download"))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{
		"output_ref": *rep.OutputRef,
		"status":     rep.Status,
	})
}

func mapErr(err error) error {
	switch {
	case service.IsValidation(err):
		return httpx.NewError(types.ErrValidation, err.Error())
	case errors.Is(err, service.ErrNotFound):
		return httpx.NewError(types.ErrNotFound, "report not found")
	case errors.Is(err, service.ErrConflict):
		return httpx.NewError(types.ErrConflict, "report conflict")
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
