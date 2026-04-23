package cpauth

import (
	"encoding/json"
	"net/http"
)

// ErrorCode represents the remote service's business error codes.
type ErrorCode int

const (
	CodeSuccess             ErrorCode = 0
	CodeBadRequest          ErrorCode = 1001
	CodeInvalidAPIKey       ErrorCode = 1002
	CodeKeyRevokedOrExpired ErrorCode = 1003
	CodeKeyNotFound         ErrorCode = 1004
	CodeRateLimitExceeded   ErrorCode = 1005
	CodeDailyQuotaExceeded  ErrorCode = 1006
	CodeResourceConflict    ErrorCode = 1007
	CodeInternalServerError ErrorCode = 1008
	CodeStorageUnavailable  ErrorCode = 1009
)

// AuthError carries structured error information from the remote service.
type AuthError struct {
	Code       ErrorCode
	Message    string
	HTTPStatus int // Derived HTTP status for convenience
}

func (e *AuthError) Error() string {
	return e.Message
}

// ErrorHandler is called when authentication fails or the remote service returns an error.
// The handler receives the original http.ResponseWriter and *http.Request, plus the structured AuthError.
// The handler is responsible for writing the HTTP response.
type ErrorHandler func(w http.ResponseWriter, err *AuthError)

// defaultErrorHandler maps known error codes to HTTP statuses and writes a JSON error body.
func defaultErrorHandler(w http.ResponseWriter, err *AuthError) {
	status := err.HTTPStatus
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  err.Message,
		"code":   err.Code,
		"status": status,
	})
}

// mapErrorCodeToHTTPStatus returns the canonical HTTP status for a given ErrorCode.
func mapErrorCodeToHTTPStatus(code ErrorCode) int {
	switch code {
	case CodeSuccess:
		return http.StatusOK
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeInvalidAPIKey:
		return http.StatusUnauthorized
	case CodeKeyRevokedOrExpired:
		return http.StatusForbidden
	case CodeKeyNotFound:
		return http.StatusNotFound
	case CodeRateLimitExceeded, CodeDailyQuotaExceeded:
		return http.StatusTooManyRequests
	case CodeResourceConflict:
		return http.StatusConflict
	case CodeInternalServerError:
		return http.StatusInternalServerError
	case CodeStorageUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// mapHTTPStatusToErrorCode returns a best-effort ErrorCode for a raw HTTP status.
func mapHTTPStatusToErrorCode(status int) ErrorCode {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeInvalidAPIKey
	case http.StatusForbidden:
		return CodeKeyRevokedOrExpired
	case http.StatusNotFound:
		return CodeKeyNotFound
	case http.StatusConflict:
		return CodeResourceConflict
	case http.StatusTooManyRequests:
		return CodeRateLimitExceeded
	case http.StatusInternalServerError:
		return CodeInternalServerError
	case http.StatusServiceUnavailable:
		return CodeStorageUnavailable
	default:
		return CodeInternalServerError
	}
}
