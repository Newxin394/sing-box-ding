package dns_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type reverseMappingTransport struct {
	kind    string
	records []mDNS.RR
}

func (s *reverseMappingTransport) Start(adapter.StartStage) error { return nil }
func (s *reverseMappingTransport) Close() error                   { return nil }
func (s *reverseMappingTransport) Tag() string                    { return "reverse-mapping-test" }
func (s *reverseMappingTransport) Dependencies() []string         { return nil }
func (s *reverseMappingTransport) Reset()                         {}
func (s *reverseMappingTransport) Type() string {
	if s.kind != "" {
		return s.kind
	}
	return "udp"
}

func (s *reverseMappingTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	response := new(mDNS.Msg)
	response.SetReply(message)
	for _, record := range s.records {
		response.Answer = append(response.Answer, mDNS.Copy(record))
	}
	return response, nil
}

func (s *reverseMappingTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(s.Exchange(ctx, message)) }()
}

func newReverseMappingRouter(t *testing.T, enabled bool) *boxDNS.Router {
	t.Helper()
	router, err := boxDNS.NewRouter(context.Background(), log.NewNOPFactory(), option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			ReverseMapping:   enabled,
			DNSClientOptions: option.DNSClientOptions{DisableCache: true},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close()) })
	return router
}

func exchangeReverseMapping(t *testing.T, router *boxDNS.Router, transport *reverseMappingTransport, message *mDNS.Msg, async bool) *mDNS.Msg {
	t.Helper()
	options := adapter.DNSQueryOptions{Transport: transport, DisableCache: true}
	if !async {
		response, err := router.Exchange(context.Background(), message, options)
		require.NoError(t, err)
		return response
	}
	type result struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan result, 1)
	router.ExchangeAsync(context.Background(), message, options, func(response *mDNS.Msg, err error) {
		done <- result{response, err}
	})
	value := <-done
	require.NoError(t, value.err)
	return value.response
}

func reverseMappingAddressRecord(address netip.Addr, owner string, ttl uint32) mDNS.RR {
	header := mDNS.RR_Header{Name: owner, Class: mDNS.ClassINET, Ttl: ttl}
	if address.Is4() {
		header.Rrtype = mDNS.TypeA
		return &mDNS.A{Hdr: header, A: net.IP(address.AsSlice())}
	}
	header.Rrtype = mDNS.TypeAAAA
	return &mDNS.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())}
}

func TestDNSReverseMappingUsesQueryDomainAcrossCNAME(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		address netip.Addr
		qtype   uint16
	}{
		{"A", netip.MustParseAddr("192.0.2.20"), mDNS.TypeA},
		{"AAAA", netip.MustParseAddr("2001:db8::20"), mDNS.TypeAAAA},
	} {
		for _, async := range []bool{false, true} {
			name := testCase.name + "/sync"
			if async {
				name = testCase.name + "/async"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				router := newReverseMappingRouter(t, true)
				message := new(mDNS.Msg)
				message.SetQuestion("source.example.", testCase.qtype)
				transport := &reverseMappingTransport{records: []mDNS.RR{
					&mDNS.CNAME{Hdr: mDNS.RR_Header{Name: "source.example.", Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET, Ttl: 300}, Target: "edge.cdn.example."},
					reverseMappingAddressRecord(testCase.address, "edge.cdn.example.", 300),
				}}
				require.Len(t, exchangeReverseMapping(t, router, transport, message, async).Answer, 2)
				domain, loaded := router.LookupReverseMapping(testCase.address)
				require.True(t, loaded)
				require.Equal(t, "source.example", domain)
			})
		}
	}
}
