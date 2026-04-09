package domain

// ParsedRequest holds all extracted and normalized data from an HTTP request.
type ParsedRequest struct {
	// Identity
	RequestID string

	// Raw extracted data (populated by Parse)
	Method      string
	Path        string
	RawQuery    string
	QueryParams map[string]string
	Headers     map[string]string // lowercase keys
	Cookies     map[string]string
	UserAgent   string
	Referer     string
	ContentType string
	ClientIP    string
	Host        string

	// Body (populated by Parse)
	RawBody       []byte
	BodyParams    []BodyParam
	BodyTruncated bool
	BodySize      int

	// Normalized data (populated by Normalize)
	NormalizedQuery      string
	NormalizedPath       string
	NormalizedParams     map[string]string
	NormalizedBody       string
	NormalizedBodyParams []BodyParam

	// Detection results (populated by Detect)
	Verdict string // "allow", "log_only", "block"
	RuleIDs []string
	Score   float32
}

// BodyParam represents a single extracted body field.
type BodyParam struct {
	Key    string
	Value  string
	Source string // "json", "form", "multipart", "raw"
}
