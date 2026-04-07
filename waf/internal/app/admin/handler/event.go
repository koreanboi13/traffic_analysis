package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// EventService defines the event query operations needed by the event handlers.
type EventService interface {
	ListEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, int64, error)
	ExportEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, error)
}

// EventsListResponse is the response for GET /api/events.
type EventsListResponse struct {
	Data   []domain.Event `json:"data"`
	Total  int64          `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
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
func HandleListEvents(eventService EventService, logger *zap.Logger) http.HandlerFunc {
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

		f := domain.EventFilter{
			IP:      q.Get("ip"),
			Verdict: q.Get("verdict"),
			RuleID:  q.Get("rule_id"),
			Limit:   limit,
			Offset:  offset,
		}

		if v := q.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ms := t.UnixMilli()
				f.From = &ms
			}
		}
		if v := q.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ms := t.UnixMilli()
				f.To = &ms
			}
		}

		events, total, err := eventService.ListEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to query events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []domain.Event{}
		}

		writeJSON(w, http.StatusOK, EventsListResponse{
			Data:   events,
			Total:  total,
			Offset: offset,
			Limit:  limit,
		})
	}
}

// HandleExportEvents returns a handler for POST /api/events/export.
func HandleExportEvents(eventService EventService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var body ExportFilter
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		limit := body.Limit
		if limit <= 0 || limit > 10000 {
			limit = 10000
		}

		f := domain.EventFilter{
			IP:      body.IP,
			Verdict: body.Verdict,
			RuleID:  body.RuleID,
			Limit:   limit,
		}

		if body.From != nil {
			ms := body.From.UnixMilli()
			f.From = &ms
		}
		if body.To != nil {
			ms := body.To.UnixMilli()
			f.To = &ms
		}

		events, err := eventService.ExportEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to export events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []domain.Event{}
		}

		writeJSON(w, http.StatusOK, events)
	}
}
