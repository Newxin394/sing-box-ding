package dns

import (
	"testing"
	"time"
)

// Cache identity stays shared, but concurrent exchanges with different
// timeout policies must not wait on the same in-flight request.
func TestDNSExchangeKeySeparatesTimeouts(t *testing.T) {
	c := &Client{}
	cacheKey := dnsCacheKey{transportTag: "test"}
	short := dnsExchangeKey{dnsCacheKey: cacheKey, timeout: time.Second}
	long := dnsExchangeKey{dnsCacheKey: cacheKey, timeout: 5 * time.Second}
	shortWait := make(chan struct{})
	longWait := make(chan struct{})
	if _, loaded := c.cacheLock.LoadOrStore(short, shortWait); loaded {
		t.Fatal("unexpected existing short exchange")
	}
	if _, loaded := c.cacheLock.LoadOrStore(long, longWait); loaded {
		t.Fatal("different timeout shared an exchange")
	}
	if got, loaded := c.cacheLock.LoadOrStore(short, make(chan struct{})); !loaded || got != shortWait {
		t.Fatal("same timeout did not reuse the exchange")
	}
	c.cacheLock.Delete(short)
	close(shortWait)
	if got, loaded := c.cacheLock.Load(long); !loaded || got != longWait {
		t.Fatal("releasing short exchange removed long exchange")
	}
	select {
	case <-longWait:
		t.Fatal("long exchange was released by short exchange")
	default:
	}
	c.cacheLock.Delete(long)
	close(longWait)
}
