package ca

import (
	"container/list"
	"crypto/tls"
)

// lru is a small, non-thread-safe LRU cache of *tls.Certificate keyed by SNI.
// The enclosing *SoftCA serializes access via its own mutex.
type lru struct {
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntry struct {
	key   string
	value *tls.Certificate
}

func newLRU(capacity int) *lru {
	if capacity < 1 {
		capacity = 1
	}
	return &lru{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element, capacity),
	}
}

func (c *lru) get(key string) (*tls.Certificate, bool) {
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*lruEntry).value, true
}

func (c *lru) add(key string, value *tls.Certificate) {
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*lruEntry).value = value
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, value: value})
	c.items[key] = el
	if c.ll.Len() > c.cap {
		if oldest := c.ll.Back(); oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*lruEntry).key)
		}
	}
}
