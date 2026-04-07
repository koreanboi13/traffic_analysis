package domain

import "github.com/google/uuid"

// Event represents a WAF event to be persisted.
type Event struct {
	// Base fields
	EventID        uuid.UUID
	Timestamp      int64 // Unix milliseconds
	RequestID      string
	ClientIP       string
	Host           string
	Method         string
	Path           string
	NormalizedPath string
	Verdict        string // "allow", "block", "log_only"
	StatusCode     uint16
	LatencyMs      float32

	// Extended fields
	RawQuery        string
	NormalizedQuery string
	RawBody         string
	NormalizedBody  string
	QueryParams     string // JSON string
	BodyParams      string // JSON string
	Headers         string // JSON string
	Cookies         string // JSON string
	UserAgent       string
	ContentType     string
	Referer         string
	BodyTruncated   uint8 // 0 or 1
	BodySize        uint32

	// Detection results
	RuleIDs []string
	Score   float32
}

// EventFilter holds query parameters for filtering events.
type EventFilter struct {
	From    *int64 // Unix ms, nil = no bound
	To      *int64 // Unix ms, nil = no bound
	IP      string
	Verdict string
	RuleID  string
	Limit   int
	Offset  int
}
