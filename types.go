package cpauth

// ValidateRequest is the payload sent to POST /v1/validate.
type ValidateRequest struct {
	APIKey     string `json:"api_key"`
	Scope      string `json:"scope"`
	HTTPMethod string `json:"http_method,omitempty"`
	URLPath    string `json:"url_path,omitempty"`
}

// ValidateMode records which validation path was used.
type ValidateMode string

const (
	// ValidateModeLocal means validation succeeded through Local.APIKey.
	ValidateModeLocal ValidateMode = "local"
	// ValidateModeRemote means validation succeeded through the remote auth service.
	ValidateModeRemote ValidateMode = "remote"
)

// ValidateResponse is the nested "data" object from the remote service.
type ValidateResponse struct {
	Valid         bool         `json:"valid"`
	ID            string       `json:"id"`
	Owner         string       `json:"owner"`
	Scopes        []string     `json:"scopes"`
	RatePerMinute int          `json:"rate_per_minute"`
	DailyQuota    int          `json:"daily_quota"`
	ValidateMode  ValidateMode `json:"-"`
}

// validateEnvelope matches the full JSON envelope from cp-api-auth.
type validateEnvelope struct {
	Code    int              `json:"code"`
	Message string           `json:"message"`
	Data    ValidateResponse `json:"data"`
}
