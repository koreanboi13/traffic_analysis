package admin

import (
	"context"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

const (
	maxListLimit   = 100
	maxExportLimit = 10000
)

// EventStorage defines the event query operations needed by EventService.
type EventStorage interface {
	QueryEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, int64, error)
	ExportEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, error)
}

// EventService handles event querying for the admin panel.
type EventService struct {
	storage EventStorage
}

// NewEventService creates an EventService backed by the given storage.
func NewEventService(storage EventStorage) *EventService {
	return &EventService{storage: storage}
}

// ListEvents returns a paginated list of events matching filter.
// The limit in filter is clamped to maxListLimit (100).
func (s *EventService) ListEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, int64, error) {
	if filter.Limit <= 0 || filter.Limit > maxListLimit {
		filter.Limit = maxListLimit
	}
	return s.storage.QueryEvents(ctx, filter)
}

// ExportEvents returns all events matching filter up to maxExportLimit (10 000).
func (s *EventService) ExportEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, error) {
	if filter.Limit <= 0 || filter.Limit > maxExportLimit {
		filter.Limit = maxExportLimit
	}
	return s.storage.ExportEvents(ctx, filter)
}
