package types

// ErrorCode is a stable, machine-readable error identifier returned in the API
// error envelope. The HTTP status mapping lives in packages/utils/httpx.
type ErrorCode string

const (
	ErrValidation       ErrorCode = "VALIDATION_ERROR"
	ErrUnauthorized     ErrorCode = "UNAUTHORIZED"
	ErrForbidden        ErrorCode = "FORBIDDEN"
	ErrNotFound         ErrorCode = "RESOURCE_NOT_FOUND"
	ErrConflict         ErrorCode = "CONFLICT"
	ErrBusinessRule     ErrorCode = "BUSINESS_RULE_VIOLATION"
	ErrRateLimited      ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrInternal         ErrorCode = "INTERNAL_ERROR"
	ErrServiceUnavail   ErrorCode = "SERVICE_UNAVAILABLE"
)
