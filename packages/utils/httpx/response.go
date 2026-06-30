// Package httpx provides the standard JSON response envelope, error-code to HTTP
// status mapping, and common middleware shared by every service. The envelope and
// error codes match the API Blueprint section 3.2 and 3.3.
package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
)

// Meta is attached to every response for traceability.
type Meta struct {
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

type successEnvelope struct {
	Data any  `json:"data"`
	Meta Meta `json:"meta"`
}

type errorBody struct {
	Code    types.ErrorCode `json:"code"`
	Message string          `json:"message"`
	Details any             `json:"details,omitempty"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
	Meta  Meta      `json:"meta"`
}

// APIError is a handler-returnable error carrying an error code and message.
type APIError struct {
	Code    types.ErrorCode
	Message string
	Details any
}

func (e *APIError) Error() string { return e.Message }

// NewError constructs an APIError.
func NewError(code types.ErrorCode, message string) *APIError {
	return &APIError{Code: code, Message: message}
}

// StatusFor maps an error code to its HTTP status.
func StatusFor(code types.ErrorCode) int {
	switch code {
	case types.ErrValidation:
		return http.StatusBadRequest
	case types.ErrUnauthorized:
		return http.StatusUnauthorized
	case types.ErrForbidden:
		return http.StatusForbidden
	case types.ErrNotFound:
		return http.StatusNotFound
	case types.ErrConflict:
		return http.StatusConflict
	case types.ErrBusinessRule:
		return http.StatusUnprocessableEntity
	case types.ErrRateLimited:
		return http.StatusTooManyRequests
	case types.ErrServiceUnavail:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// WriteJSON writes data wrapped in the success envelope with the given status.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	env := successEnvelope{
		Data: data,
		Meta: Meta{RequestID: RequestID(r.Context()), Timestamp: time.Now()},
	}
	write(w, status, env)
}

// WriteError writes err as the standard error envelope. err may be an *APIError;
// any other error is reported as a generic INTERNAL_ERROR.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr, ok := err.(*APIError)
	if !ok {
		apiErr = &APIError{Code: types.ErrInternal, Message: "internal server error"}
	}
	env := errorEnvelope{
		Error: errorBody{Code: apiErr.Code, Message: apiErr.Message, Details: apiErr.Details},
		Meta:  Meta{RequestID: RequestID(r.Context()), Timestamp: time.Now()},
	}
	write(w, StatusFor(apiErr.Code), env)
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// DecodeJSON decodes the request body into dst, returning a VALIDATION_ERROR on
// malformed input.
func DecodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return NewError(types.ErrValidation, "invalid request body: "+err.Error())
	}
	return nil
}
