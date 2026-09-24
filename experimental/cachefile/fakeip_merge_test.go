package cachefile

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestDeleteDNSCacheDoesNotDeleteNewerValue(t *testing.T) {
	t.Parallel()
	c := newTestCacheFile(t)
	key := saveCacheKey{"transport", "example.test.", 1}
	newer := []byte("new-response")
	c.queueDNSCache(key.TransportName, key.QuestionName, key.QType, newer, time.Now().Add(time.Hour))
	c.Flush()
	c.DeleteDNSCache(key.TransportName, key.QuestionName, key.QType, []byte("old-response"))
	got, _, ok := c.LoadDNSCache(key.TransportName, key.QuestionName, key.QType)
	if !ok || !bytes.Equal(got, newer) {
		t.Fatalf("new cache value lost: %q, loaded=%v", got, ok)
	}
}

func TestPendingFakeIPInvalidationMarker(t *testing.T) {
	t.Parallel()
	c := newTestCacheFile(t)
	address := mustTestAddr("198.18.0.9")
	c.queueFakeIP(address, "old.example")
	c.queueFakeIP(address, "new.example")
	if _, ok := c.FakeIPLoadDomain("old.example", false); ok {
		t.Fatal("old pending reverse mapping remained valid")
	}
	if got, ok := c.FakeIPLoadDomain("new.example", false); !ok || got != address {
		t.Fatalf("new mapping = %s, %v", got, ok)
	}
}

func mustTestAddr(value string) netip.Addr { return netip.MustParseAddr(value) }
