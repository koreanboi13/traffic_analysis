package events

import (
	"github.com/google/uuid"
)

// Event представляет событие WAF, которое будет записано в ClickHouse
type Event struct {
	// === Базовые поля ===
	EventID        uuid.UUID `json:"event_id" db:"event_id"`                         // Идентификатор события (UUID)
	Timestamp      int64     `json:"timestamp" db:"timestamp"`                       // Метка времени (Unix миллисекунды)
	RequestID      string    `json:"request_id" db:"request_id"`                     // ID запроса
	ClientIP       string    `json:"client_ip" db:"client_ip"`                       // IP клиента
	Host           string    `json:"host" db:"host"`                                 // Хост
	Method         string    `json:"method" db:"method"`                             // HTTP метод
	Path           string    `json:"path" db:"path"`                                 // Путь запроса
	NormalizedPath string    `json:"normalized_path,omitempty" db:"normalized_path"` // Нормализованный путь
	Verdict        string    `json:"verdict" db:"verdict"`                           // Вердикт: "allow", "block" или "log_only"
	StatusCode     uint16    `json:"status_code" db:"status_code"`                   // HTTP код ответа
	LatencyMs      float32   `json:"latency_ms" db:"latency_ms"`                     // Задержка в миллисекундах

	// === Расширенные поля ===
	RawQuery        string `json:"raw_query,omitempty" db:"raw_query"`               // Сырая query string
	NormalizedQuery string `json:"normalized_query,omitempty" db:"normalized_query"` // Нормализованная query string
	RawBody         string `json:"raw_body,omitempty" db:"raw_body"`                 // Сырое тело
	NormalizedBody  string `json:"normalized_body,omitempty" db:"normalized_body"`   // Нормализованное тело
	QueryParams     string `json:"query_params,omitempty" db:"query_params"`         // Query-параметры (JSON строка)
	BodyParams      string `json:"body_params,omitempty" db:"body_params"`           // Body-параметры (JSON строка)
	Headers         string `json:"headers,omitempty" db:"headers"`                   // Заголовки (JSON строка)
	Cookies         string `json:"cookies,omitempty" db:"cookies"`                   // Cookies (JSON строка)
	UserAgent       string `json:"user_agent,omitempty" db:"user_agent"`             // User-Agent
	ContentType     string `json:"content_type,omitempty" db:"content_type"`         // Content-Type
	Referer         string `json:"referer,omitempty" db:"referer"`                   // Referer
	BodyTruncated   uint8  `json:"body_truncated" db:"body_truncated"`               // Флаг truncation тела (0 или 1)
	BodySize        uint32 `json:"body_size" db:"body_size"`                         // Размер тела

	// === Плейсхолдеры для Phase 4 ===
	RuleIDs []string `json:"triggered_rules_ids,omitempty" db:"triggered_rules_ids"` // Массив ID сработавших правил
	Score   float32  `json:"risk_score,omitempty" db:"risk_score"`                   // Risk score
}
