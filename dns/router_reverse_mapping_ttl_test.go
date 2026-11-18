package dns_test

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSReverseMappingLifetime(t *testing.T) {
	for _, async := range []bool{false, true} {
		mode := "sync"
		if async {
			mode = "async"
		}
		t.Run(mode, func(t *testing.T) {
			for _, behavior := range []string{"zero TTL expires", "shorter TTL preserves mapping", "longer TTL extends mapping", "different domain replaces mapping"} {
				t.Run(behavior, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						router := newReverseMappingRouter(t, true)
						address := netip.MustParseAddr("192.0.2.30")
						message := new(mDNS.Msg)
						message.SetQuestion("source.example.", mDNS.TypeA)
						transport := &reverseMappingTransport{}
						exchange := func(ttl uint32) {
							transport.records = []mDNS.RR{reverseMappingAddressRecord(address, message.Question[0].Name, ttl)}
							exchangeReverseMapping(t, router, transport, message, async)
						}
						switch behavior {
						case "zero TTL expires":
							exchange(0)
							domain, loaded := router.LookupReverseMapping(address)
							require.True(t, loaded)
							require.Equal(t, "source.example", domain)
							time.Sleep(2 * time.Second)
							_, loaded = router.LookupReverseMapping(address)
							require.False(t, loaded, "zero TTL must not create an immortal reverse mapping")
						case "shorter TTL preserves mapping":
							exchange(60)
							time.Sleep(10 * time.Second)
							exchange(1)
							time.Sleep(2 * time.Second)
							domain, loaded := router.LookupReverseMapping(address)
							require.True(t, loaded, "a repeated response must not shorten an existing longer mapping")
							require.Equal(t, "source.example", domain)
						case "longer TTL extends mapping":
							exchange(1)
							exchange(5)
							time.Sleep(2 * time.Second)
							domain, loaded := router.LookupReverseMapping(address)
							require.True(t, loaded)
							require.Equal(t, "source.example", domain)
						case "different domain replaces mapping":
							exchange(60)
							message.SetQuestion("replacement.example.", mDNS.TypeA)
							exchange(1)
							domain, loaded := router.LookupReverseMapping(address)
							require.True(t, loaded)
							require.Equal(t, "replacement.example", domain)
							time.Sleep(2 * time.Second)
							_, loaded = router.LookupReverseMapping(address)
							require.False(t, loaded)
						}
					})
				})
			}
		})
	}
}

func TestDNSReverseMappingExcludesFakeIPAndDisabledCache(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		kind    string
		enabled bool
	}{
		{"fakeip", "fakeip", true},
		{"disabled", "udp", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := newReverseMappingRouter(t, testCase.enabled)
			address := netip.MustParseAddr("198.18.0.30")
			message := new(mDNS.Msg)
			message.SetQuestion("source.example.", mDNS.TypeA)
			transport := &reverseMappingTransport{kind: testCase.kind, records: []mDNS.RR{reverseMappingAddressRecord(address, "source.example.", 300)}}
			exchangeReverseMapping(t, router, transport, message, false)
			_, loaded := router.LookupReverseMapping(address)
			require.False(t, loaded)
		})
	}
}
