package events

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Storage определяет интерфейс для записи событий в ClickHouse
type Storage interface {
	InsertBatch(ctx context.Context, events []Event) error
}

// Writer выполняет пакетную запись событий в ClickHouse
type Writer struct {
	storage      Storage
	batchSize    int
	flushInterval time.Duration
	logger       *zap.Logger
	
	eventCh      chan Event
	doneCh       chan struct{}
}

// NewWriter создаёт новый Writer
func NewWriter(storage Storage, batchSize int, flushInterval time.Duration, logger *zap.Logger) *Writer {
	// Буферизованный канал с запасом: batchSize * 10
	bufferSize := batchSize * 10
	
	return &Writer{
		storage:       storage,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		logger:        logger,
		eventCh:       make(chan Event, bufferSize),
		doneCh:        make(chan struct{}),
	}
}

// Start запускает горутину с основным циклом обработки событий
func (w *Writer) Start(ctx context.Context) {
	go w.run(ctx)
}

// Send отправляет событие в канал (неблокирующая операция)
func (w *Writer) Send(event Event) {
	// Устанавливаем timestamp, если он не задан
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}
	
	// Генерируем UUID, если он не задан
	if event.EventID == uuid.Nil {
		event.EventID = uuid.New()
	}
	
	select {
	case w.eventCh <- event:
		// Событие успешно отправлено в канал
	default:
		// Канал полон - дропаем событие
		w.logger.Warn("event channel is full, dropping event",
			zap.String("request_id", event.RequestID),
			zap.String("client_ip", event.ClientIP),
			zap.String("method", event.Method),
			zap.String("path", event.Path),
		)
	}
}

// Stop останавливает writer и ждёт завершения обработки
func (w *Writer) Stop() {
	close(w.eventCh)
	<-w.doneCh
	w.logger.Info("event writer stopped")
}

// run основной цикл обработки событий
func (w *Writer) run(ctx context.Context) {
	defer close(w.doneCh)
	
	// Локальный буфер для накопления событий
	buffer := make([]Event, 0, w.batchSize)
	
	// Таймер для периодического flush
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
				// Канал закрыт - дописываем оставшиеся события и выходим
				if len(buffer) > 0 {
					w.flushWithTimeout(buffer)
				}
				w.logger.Info("event channel closed, writer shutting down")
				return
			}
			
			// Добавляем событие в буфер
			buffer = append(buffer, event)
			
			// Если буфер достиг batch_size - делаем flush
			if len(buffer) >= w.batchSize {
				w.flushWithTimeout(buffer)
				// Создаём новый буфер
				buffer = make([]Event, 0, w.batchSize)
			}
			
		case <-ticker.C:
			// По таймеру: если в буфере есть события - делаем flush
			if len(buffer) > 0 {
				w.flushWithTimeout(buffer)
				// Создаём новый буфер
				buffer = make([]Event, 0, w.batchSize)
			}
			
		case <-ctx.Done():
			// Контекст отменён - завершаем работу
			w.logger.Info("context cancelled, flushing remaining events and shutting down")
			
			// Читаем все оставшиеся события из канала
			for event := range w.eventCh {
				buffer = append(buffer, event)
			}
			
			// Flush оставшихся событий
			if len(buffer) > 0 {
				w.flushWithTimeout(buffer)
			}
			
			w.logger.Info("writer shutdown completed")
			return
		}
	}
}

// flushWithTimeout выполняет flush с таймаутом 10 секунд
func (w *Writer) flushWithTimeout(events []Event) {
	if len(events) == 0 {
		return
	}
	
	// Создаём контекст с таймаутом 10 секунд
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Пытаемся записать пачку событий
	err := w.storage.InsertBatch(ctx, events)
	if err != nil {
		// Логируем ошибку, но не прерываем работу
		w.logger.Error("failed to insert batch of events",
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		
		// Дополнительно логируем первое событие для диагностики
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