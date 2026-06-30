package auth

import (
	"context"
	"net/http"
	"strings"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/httpx"
)

type ctxKey string

const claimsKey ctxKey = "auth_claims"

// Middleware validates the Bearer token on every request and stores the verified
// claims on the context. Requests without a valid token receive 401.
//
// In the deployed architecture Kong validates the JWT at the edge and injects
// X-Tenant-ID; this middleware provides the same guarantees for direct service
// access and local development.
func (i *Issuer) Middleware() httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				httpx.WriteError(w, r, httpx.NewError(types.ErrUnauthorized, "missing bearer token"))
				return
			}
			claims, err := i.Verify(raw)
			if err != nil {
				httpx.WriteError(w, r, httpx.NewError(types.ErrUnauthorized, "invalid or expired token"))
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission returns middleware that rejects requests whose claims lack the
// given permission with 403. It must be chained after Middleware.
func RequirePermission(perm string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := ClaimsFrom(r.Context())
			if c == nil || !c.HasPermission(perm) {
				httpx.WriteError(w, r, httpx.NewError(types.ErrForbidden, "insufficient permission: "+perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFrom returns the verified claims stored on ctx, or nil.
func ClaimsFrom(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// TenantID returns the tenant id from the request claims, or "".
func TenantID(ctx context.Context) string {
	if c := ClaimsFrom(ctx); c != nil {
		return c.TenantID
	}
	return ""
}

// ActorID returns the subject (user id) from the request claims, or "".
func ActorID(ctx context.Context) string {
	if c := ClaimsFrom(ctx); c != nil {
		return c.Subject
	}
	return ""
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
