// Package approval holds one HTTP request at the proxy until a human reviews it.
// Decisions exist only in memory and are consumed exactly once. A restart,
// disconnect, denial, or timeout always prevents forwarding.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrDenied      = errors.New("request approval denied")
	ErrTimeout     = errors.New("request approval timed out")
	ErrQueueFull   = errors.New("request approval queue full")
	ErrNotFound    = errors.New("request approval not found")
	ErrUnavailable = errors.New("request approval unavailable")
)

const Timeout = 2 * time.Minute
const MaxPendingPerVault = 32

// Request contains the metadata shown to a reviewer. The query, headers,
// body, and credential values are deliberately excluded.
type Request struct {
	ID        string    `json:"id"`
	VaultID   string    `json:"-"`
	Service   string    `json:"service"`
	ActorID   string    `json:"actor_id"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	BodyBytes int64     `json:"body_bytes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type pending struct {
	request  Request
	decision chan bool
	ctx      context.Context
}

type Manager struct {
	mu      sync.Mutex
	pending map[string]*pending
}

func NewManager() *Manager { return &Manager{pending: make(map[string]*pending)} }

// Wait registers one request and blocks until a decision, cancellation, or
// deadline. No approval token is returned to the caller or agent.
func (m *Manager) Wait(ctx context.Context, request Request) error {
	if m == nil {
		return ErrUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ErrUnavailable
	}
	request.ID = hex.EncodeToString(id[:])
	request.CreatedAt = time.Now().UTC()
	request.ExpiresAt = request.CreatedAt.Add(Timeout)
	p := &pending{request: request, decision: make(chan bool, 1), ctx: ctx}
	m.mu.Lock()
	count := 0
	for _, item := range m.pending {
		if item.request.VaultID == request.VaultID {
			count++
		}
	}
	if count >= MaxPendingPerVault {
		m.mu.Unlock()
		return ErrQueueFull
	}
	m.pending[request.ID] = p
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.pending, request.ID); m.mu.Unlock() }()

	timer := time.NewTimer(Timeout)
	defer timer.Stop()
	select {
	case approved := <-p.decision:
		if approved {
			if err := ctx.Err(); err != nil {
				return err
			}
			return nil
		}
		return ErrDenied
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrTimeout
	}
}

func (m *Manager) List(vaultID string) []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Request, 0)
	for _, item := range m.pending {
		if item.request.VaultID == vaultID {
			result = append(result, item.request)
		}
	}
	return result
}

// Decide consumes the pending decision under the lock, so a second reviewer
// cannot approve or reject the same request again.
func (m *Manager) Decide(vaultID, id string, approve bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pending[id]
	if !ok || p.request.VaultID != vaultID {
		return ErrNotFound
	}
	if time.Now().After(p.request.ExpiresAt) || p.ctx.Err() != nil {
		delete(m.pending, id)
		return ErrNotFound
	}
	delete(m.pending, id)
	p.decision <- approve
	return nil
}
