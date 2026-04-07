package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	chstorage "github.com/koreanboi13/traffic_analysis/waf/internal/events/clickhouse"
	"go.uber.org/zap"
)

// EventsListResponse is the response for GET /api/events.
type EventsListResponse struct {
	Data   []chstorage.Event `json:"data"`
	Total  int64             `json:"total"`
	Offset int               `json:"offset"`
	Limit  int               `json:"limit"`
}

// ExportFilter is the request body for POST /api/events/export.
type ExportFilter struct {
	From    *time.Time `json:"from"`
	To      *time.Time `json:"to"`
	IP      string     `json:"ip"`
	Verdict string     `json:"verdict"`
	RuleID  string     `json:"rule_id"`
	Limit   int        `json:"limit"`
}

// HandleListEvents returns a handler for GET /api/events with query-param filtering.
func HandleListEvents(storage *chstorage.Storage, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit := 20
		if v := q.Get("limit"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if limit > 100 {
			limit = 100
		}

		offset := 0
		if v := q.Get("offset"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		f := chstorage.EventFilter{
			IP:      q.Get("ip"),
			Verdict: q.Get("verdict"),
			RuleID:  q.Get("rule_id"),
			Limit:   limit,
			Offset:  offset,
		}

		if v := q.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.From = &t
			}
		}
		if v := q.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.To = &t
			}
		}

		events, total, err := storage.QueryEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to query events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []chstorage.Event{}
		}

		resp := EventsListResponse{
			Data:   events,
			Total:  total,
			Offset: offset,
			Limit:  limit,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleExportEvents returns a handler for POST /api/events/export.
func HandleExportEvents(storage *chstorage.Storage, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body ExportFilter
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		limit := body.Limit
		if limit <= 0 || limit > 10000 {
			limit = 10000
		}

		f := chstorage.EventFilter{
			From:    body.From,
			To:      body.To,
			IP:      body.IP,
			Verdict: body.Verdict,
			RuleID:  body.RuleID,
			Limit:   limit,
		}

		events, err := storage.ExportEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to export events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []chstorage.Event{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}
