//go:build with_quic

package httpclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHTTP3BrokenAuthorityIsolation(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443")
	if !transport.h3Broken("a.example:443") {
		t.Fatal("a.example:443 should be broken after mark")
	}
	if transport.h3Broken("b.example:443") {
		t.Fatal("b.example:443 must not be affected by marking a.example")
	}
}

func TestHTTP3BrokenBackoffPerAuthority(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443")
	if transport.broken["a.example:443"].backoff != 5*time.Minute {
		t.Fatalf("first mark should set backoff to 5m, got %v", transport.broken["a.example:443"].backoff)
	}
	transport.markH3Broken("a.example:443")
	if transport.broken["a.example:443"].backoff != 10*time.Minute {
		t.Fatalf("second mark should double backoff to 10m, got %v", transport.broken["a.example:443"].backoff)
	}
	transport.markH3Broken("a.example:443")
	if transport.broken["a.example:443"].backoff != 20*time.Minute {
		t.Fatalf("third mark should double to 20m, got %v", transport.broken["a.example:443"].backoff)
	}

	if _, found := transport.broken["b.example:443"]; found {
		t.Fatal("marking a.example must not leak into b.example backoff state")
	}

	transport.markH3Broken("b.example:443")
	if transport.broken["b.example:443"].backoff != 5*time.Minute {
		t.Fatalf("b.example first mark should start at 5m independent of a.example, got %v", transport.broken["b.example:443"].backoff)
	}
}

func TestHTTP3BrokenBackoffCap(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.broken["a.example:443"] = http3BrokenEntry{backoff: 48 * time.Hour, until: time.Now().Add(48 * time.Hour)}
	transport.markH3Broken("a.example:443")
	if transport.broken["a.example:443"].backoff != 48*time.Hour {
		t.Fatalf("backoff must cap at 48h, got %v", transport.broken["a.example:443"].backoff)
	}
}

func TestHTTP3BrokenClearDeletesEntry(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("a.example:443")
	transport.markH3Broken("b.example:443")
	transport.clearH3Broken("a.example:443")

	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("clearH3Broken must delete the entry")
	}
	if !transport.h3Broken("b.example:443") {
		t.Fatal("clearing a.example must not affect b.example")
	}
}

func TestHTTP3BrokenExpiredEntryGarbageCollected(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.broken["a.example:443"] = http3BrokenEntry{
		backoff: 5 * time.Minute,
		until:   time.Now().Add(-time.Second),
	}
	if transport.h3Broken("a.example:443") {
		t.Fatal("expired entry must report not broken")
	}
	if _, found := transport.broken["a.example:443"]; found {
		t.Fatal("expired entry must be garbage-collected on read")
	}
}

func TestHTTP3BrokenEmptyAuthorityNoOp(t *testing.T) {
	transport := &http3FallbackTransport{broken: make(map[string]http3BrokenEntry)}

	transport.markH3Broken("")
	if len(transport.broken) != 0 {
		t.Fatalf("markH3Broken must ignore empty authority, got %d entries", len(transport.broken))
	}
	if transport.h3Broken("") {
		t.Fatal("h3Broken must return false for empty authority")
	}
	transport.clearH3Broken("")
}

func TestHTTP3BrokenCacheIsBounded(t *testing.T) {
	now := time.Now()
	transport := &http3FallbackTransport{
		broken: map[string]http3BrokenEntry{
			"old.example:443": {until: now.Add(5 * time.Minute), backoff: 5 * time.Minute},
			"new.example:443": {until: now.Add(10 * time.Minute), backoff: 5 * time.Minute},
		},
		maxBroken: 2,
	}
	transport.markH3Broken("latest.example:443")
	if len(transport.broken) != 2 {
		t.Fatalf("broken authority cache must remain bounded, got %d entries", len(transport.broken))
	}
	if _, found := transport.broken["old.example:443"]; found {
		t.Fatal("oldest broken authority must be evicted when cache is full")
	}
	if _, found := transport.broken["latest.example:443"]; !found {
		t.Fatal("new broken authority must be retained")
	}
}

func TestShouldMarkH3Broken(t *testing.T) {
	if shouldMarkH3Broken(context.Canceled) {
		t.Fatal("caller cancellation must not poison H3 state")
	}
	if shouldMarkH3Broken(context.DeadlineExceeded) {
		t.Fatal("caller deadline must not poison H3 state")
	}
	if !shouldMarkH3Broken(errors.New("network failure")) {
		t.Fatal("transport failure must mark H3 state")
	}
}
