package cpauth

// ValidateRequest is the payload sent to POST /v1/validate.
type ValidateRequest struct {
	APIKey string `json:"api_key"`
	Scope  string `json:"scope"`
}

// ValidateResponse is the nested "data" object from the remote service.
type ValidateResponse struct {
	Valid         bool     `json:"valid"`
	ID            string   `json:"id"`
	Owner         string   `json:"owner"`
	Scopes        []string `json:"scopes"`
	RatePerMinute int      `json:"rate_per_minute"`
	DailyQuota    int      `json:"daily_quota"`
}

// validateEnvelope matches the full JSON envelope from cp-api-auth.
type validateEnvelope struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Data    ValidateResponse `json:"data"`
}
