package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// The udp_outbound / udp_fallback_outbound checks run before any service is
// pulled from the context, so a bare context is enough to exercise them.

func TestSelectorUDPDelegationValidation(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("selector")

	t.Run("fallback without primary", func(t *testing.T) {
		_, err := NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:           []string{"a"},
				UDPFallbackOutbound: "direct",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires udp_outbound")
	})

	t.Run("primary references itself", func(t *testing.T) {
		_, err := NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:   []string{"a"},
				UDPOutbound: "sel",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not reference itself")
	})

	t.Run("fallback references itself", func(t *testing.T) {
		_, err := NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:           []string{"a"},
				UDPOutbound:         "direct",
				UDPFallbackOutbound: "sel",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not reference itself")
	})
}

func TestURLTestUDPDelegationValidation(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("urltest")

	t.Run("fallback without primary", func(t *testing.T) {
		_, err := NewURLTest(context.Background(), nil, logger, "ut", option.URLTestOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:           []string{"a"},
				UDPFallbackOutbound: "direct",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires udp_outbound")
	})

	t.Run("primary references itself", func(t *testing.T) {
		_, err := NewURLTest(context.Background(), nil, logger, "ut", option.URLTestOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:   []string{"a"},
				UDPOutbound: "ut",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not reference itself")
	})

	t.Run("fallback references itself", func(t *testing.T) {
		_, err := NewURLTest(context.Background(), nil, logger, "ut", option.URLTestOutboundOptions{
			GroupCommonOption: option.GroupCommonOption{
				Outbounds:           []string{"a"},
				UDPOutbound:         "direct",
				UDPFallbackOutbound: "ut",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not reference itself")
	})
}

// A valid combination must be accepted, and construction must not depend on any
// service being present in the context.
func TestUDPDelegationValidCombinationAccepted(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("group")
	_, err := NewSelector(context.Background(), nil, logger, "sel", option.SelectorOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{
			Outbounds:           []string{"a"},
			UDPOutbound:         "udp-primary",
			UDPFallbackOutbound: "udp-fallback",
		},
	})
	require.NoError(t, err)
}
