package oauth

import "golang.org/x/sync/singleflight"

// RefreshResult is the outcome of a single refresh attempt, shared across all
// concurrent callers for the same key via singleflight.
type RefreshResult struct {
	AccessToken string
	Refreshed   bool
	Err         error
}

// Refresher deduplicates concurrent token refreshes using singleflight so that
// multiple goroutines waiting on the same credential see one network call.
type Refresher struct {
	group singleflight.Group
}

// NewRefresher returns a ready-to-use Refresher.
func NewRefresher() *Refresher {
	return &Refresher{}
}

// Do executes fn at most once for the given key at any point in time.
// Concurrent callers with the same key block until the first caller's fn
// returns, then all receive the same RefreshResult.
func (r *Refresher) Do(key string, fn func() RefreshResult) RefreshResult {
	v, _, _ := r.group.Do(key, func() (interface{}, error) {
		res := fn()
		return res, nil
	})
	return v.(RefreshResult)
}
