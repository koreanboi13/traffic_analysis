package eventwriter

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// BatchInserter defines the storage operation needed by Writer.
type BatchInserter interface {
	InsertBatch(ctx context.Context, events []domain.Event) error
}

// Writer performs batched async writes of domain.Event to storage.
// It satisfies the transport/proxy.EventSender interface via the Send method.
type Writer struct {
	storage       BatchInserter
	batchSize     int
	flushInterval time.Duration
	logger        *zap.Logger

	eventCh chan domain.Event
	doneCh  chan struct{}
}

// NewWriter creates a new Writer.
// bufferSize is set to batchSize * 10 to absorb traffic bursts.
func NewWriter(storage BatchInserter, batchSize int, flushInterval time.Duration, logger *zap.Logger) *Writer {
	bufferSize := batchSize * 10

	return &Writer{
		storage:       storage,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		logger:        logger,
		eventCh:       make(chan domain.Event, bufferSize),
		doneCh:        make(chan struct{}),
	}
}

// Start launches the background processing goroutine.
func (w *Writer) Start() {
	go w.run()
}

// Send enqueues an event for async writing (non-blocking).
// If EventID or Timestamp are zero-valued they are populated before enqueueing.
// If the internal channel is full the event is dropped and a warning is logged.
func (w *Writer) Send(event domain.Event) {
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}

	if event.EventID == uuid.Nil {
		event.EventID = uuid.New()
	}

	select {
	case w.eventCh <- event:
		// event accepted
	default:
		// channel full — drop to avoid blocking the request path
		w.logger.Warn("event channel is full, dropping event",
			zap.String("request_id", event.RequestID),
			zap.String("client_ip", event.ClientIP),
			zap.String("method", event.Method),
			zap.String("path", event.Path),
		)
	}
}

// Stop closes the event channel, waits for the run loop to flush remaining
// events, and returns only after the goroutine has exited.
func (w *Writer) Stop() {
	close(w.eventCh)
	<-w.doneCh
	w.logger.Info("event writer stopped")
}

// run is the main loop — reads from eventCh and accumulates into a local
// buffer, flushing whenever the batch size is reached or the ticker fires.
func (w *Writer) run() {
	defer close(w.doneCh)

	buffer := make([]domain.Event, 0, w.batchSize)

	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	w.logger.Info("event writer started",
		zap.Int("batch_size", w.batchSize),
		zap.Duration("flush_interval", w.flushInterval),
	)

	for {
		select {
		case event, ok := <-w.eventCh:
			if !ok {
				// Channel closed by Stop() — flush remaining and exit.
				if len(buffer) > 0 {
					w.flushWithTimeout(buffer)
				}
				w.logger.Info("event writer shutdown completed")
				return
			}

			buffer = append(buffer, event)

			if len(buffer) >= w.batchSize {
				w.flushWithTimeout(buffer)
				buffer = make([]domain.Event, 0, w.batchSize)
			}

		case <-ticker.C:
			if len(buffer) > 0 {
				w.flushWithTimeout(buffer)
				buffer = make([]domain.Event, 0, w.batchSize)
			}
		}
	}
}

// flushWithTimeout writes a batch to storage with a 10-second deadline.
// Errors are logged but do not stop the writer.
func (w *Writer) flushWithTimeout(events []domain.Event) {
	if len(events) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := w.storage.InsertBatch(ctx, events)
	if err != nil {
		w.logger.Error("failed to insert batch of events",
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)

		if len(events) > 0 {
			w.logger.Debug("first event in failed batch",
				zap.String("event_id", events[0].EventID.String()),
				zap.String("request_id", events[0].RequestID),
				zap.String("method", events[0].Method),
				zap.String("path", events[0].Path),
			)
		}
		return
	}

	w.logger.Debug("successfully flushed events batch",
		zap.Int("batch_size", len(events)),
	)
}
