// Package events fans changes out to live clients (WebSocket, SSE) and
// in-process / Redis domain observers (EventBus).
package events

import (
	"context"
	"strings"
	"sync"
)

// Event says that something happened or changed.
type Event struct {
	Type string `json:"type"` // e.g. note.changed, invoice.paid
	ID   string `json:"id,omitempty"`
	Data any    `json:"data,omitempty"`
}

type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func New() *Bus { return &Bus{subs: map[chan Event]struct{}{}} }

// Publish delivers an event to every subscriber (of every gateway, with
// Redis). It never blocks: a subscriber too slow to keep up misses events.
func (b *Bus) Publish(ctx context.Context, typ, id string) {
	b.PublishEvent(ctx, Event{Type: typ, ID: id})
}

// PublishEvent delivers a full Event with optional Data payload to subscribers.
func (b *Bus) PublishEvent(ctx context.Context, ev Event) {
	b.deliver(ev)
}

func (b *Bus) deliver(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribe returns a channel of events and the function that ends the
// subscription.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// On registers an observer callback for events matching a prefix (e.g. "task." or "*").
// Returns a cancel function to unregister.
func (b *Bus) On(prefix string, fn func(ev Event)) func() {
	ch, cancel := b.Subscribe()
	go func() {
		for ev := range ch {
			if prefix == "" || prefix == "*" || strings.HasPrefix(ev.Type, prefix) {
				fn(ev)
			}
		}
	}()
	return cancel
}
