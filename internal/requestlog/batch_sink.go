package requestlog

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Defaults tuned for the near-real-time tailing UI: batches land inside
// one ~3s UI poll interval while keeping DB writes coalesced under
// bursty traffic. Operators can override via BatchSinkConfig.
const (
	defaultBufferSize   = 1024
	defaultBatchSize    = 100
	defaultFlushEvery   = 250 * time.Millisecond
	defaultShutdownWait = 3 * time.Second
)

// batchStore is the narrow surface BatchSink needs; lets tests
// substitute a fake without standing up the full Store interface.
type batchStore interface {
	InsertRequestLogs(ctx context.Context, rows []store.RequestLog) error
}

// BatchSinkConfig controls the BatchSink's batching behavior. Zero
// fields fall back to sensible defaults.
type BatchSinkConfig struct {
	BufferSize   int
	BatchSize    int
	FlushEvery   time.Duration
	ShutdownWait time.Duration

	// OnCommit is invoked (if non-nil) after a batch is successfully
	// inserted. Reserved for the future broadcaster that will feed an
	// SSE endpoint — unused today. Callback runs on the worker
	// goroutine, so implementations must not block.
	OnCommit func(batch []Record)
}

// BatchSink buffers records in a bounded channel and flushes them to
// the database in batches. Non-blocking on the hot path: if the buffer is
// full, the record is dropped and the drop counter is incremented.
type BatchSink struct {
	store   batchStore
	logger  *slog.Logger
	cfg     BatchSinkConfig
	in      chan Record
	done    chan struct{}
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// NewBatchSink constructs a sink and starts its background worker.
// Call Close to flush and stop.
func NewBatchSink(s batchStore, logger *slog.Logger, cfg BatchSinkConfig) *BatchSink {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = defaultFlushEvery
	}
	if cfg.ShutdownWait <= 0 {
		cfg.ShutdownWait = defaultShutdownWait
	}
	sk := &BatchSink{
		store:  s,
		logger: logger,
		cfg:    cfg,
		in:     make(chan Record, cfg.BufferSize),
		done:   make(chan struct{}),
	}
	sk.wg.Add(1)
	go sk.run()
	return sk
}

// Record implements Sink. Non-blocking: drops if the buffer is full.
func (s *BatchSink) Record(_ context.Context, r Record) {
	select {
	case s.in <- r:
	default:
		n := s.dropped.Add(1)
		// Warn on the first drop of each power-of-two to surface
		// overload without flooding the log under sustained pressure.
		if s.logger != nil && isLogBoundary(n) {
			s.logger.Warn("request_log buffer overflow: dropping records",
				"total_dropped", n,
				"buffer_size", s.cfg.BufferSize,
			)
		}
	}
}

// Dropped returns the total records dropped due to buffer overflow
// since construction. Exposed for metrics and tests.
func (s *BatchSink) Dropped() uint64 { return s.dropped.Load() }

// Close drains pending records and stops the worker. Honors the parent
// context for its own deadline; falls back to ShutdownWait.
func (s *BatchSink) Close(ctx context.Context) error {
	close(s.done)

	wait := s.cfg.ShutdownWait
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	doneCh := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		return nil
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func (s *BatchSink) run() {
	defer s.wg.Done()

	batch := make([]Record, 0, s.cfg.BatchSize)
	ticker := time.NewTicker(s.cfg.FlushEvery)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.commit(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-s.done:
			// Drain whatever is already buffered before exiting.
			for {
				select {
				case r := <-s.in:
					batch = append(batch, r)
					if len(batch) >= s.cfg.BatchSize {
						s.commit(batch)
						batch = batch[:0]
					}
				default:
					flush()
					return
				}
			}
		case <-ticker.C:
			flush()
		case r := <-s.in:
			batch = append(batch, r)
			if len(batch) >= s.cfg.BatchSize {
				s.commit(batch)
				batch = batch[:0]
			}
		}
	}
}

// commit persists batch and fires the OnCommit hook on success. Errors
// are logged; we do not retry — losing a small slice of logs is
// acceptable, but blocking the worker on a failing DB is not.
func (s *BatchSink) commit(batch []Record) {
	rows := make([]store.RequestLog, len(batch))
	for i, r := range batch {
		rows[i] = toStoreRow(r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.InsertRequestLogs(ctx, rows); err != nil {
		if s.logger != nil {
			s.logger.Error("request_logs insert failed",
				"err", err.Error(),
				"batch_size", len(batch),
			)
		}
		return
	}
	if s.cfg.OnCommit != nil {
		// Worker reuses `batch` after commit returns; hand the
		// callback its own copy so slow consumers don't see mutations.
		cp := make([]Record, len(batch))
		copy(cp, batch)
		s.cfg.OnCommit(cp)
	}
}

// isLogBoundary reports true when n is a power of two. Used to throttle
// overflow warnings to 1, 2, 4, 8, ... dropped records.
func isLogBoundary(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}
