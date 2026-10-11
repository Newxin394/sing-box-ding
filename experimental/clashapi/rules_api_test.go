package clashapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/render"
	"github.com/stretchr/testify/require"
)

type testClashRule struct {
	adapter.Rule
	ruleType string
	payload  string
	proxy    string
	uuid     string
	disabled bool
}

func (r *testClashRule) Type() string              { return r.ruleType }
func (r *testClashRule) String() string            { return r.payload }
func (r *testClashRule) UUID() string              { return r.uuid }
func (r *testClashRule) Disabled() bool            { return r.disabled }
func (r *testClashRule) SetDisabled(disabled bool) { r.disabled = disabled }
func (r *testClashRule) Action() adapter.RuleAction {
	return &testClashRuleAction{proxy: r.proxy}
}

type testClashRuleAction struct {
	adapter.RuleAction
	proxy string
}

func (a *testClashRuleAction) String() string { return a.proxy }
func (a *testClashRuleAction) Type() string   { return "route" }

type testClashRuleRouter struct {
	adapter.Router
	rules []adapter.Rule
}

func (r *testClashRuleRouter) Rules() []adapter.Rule { return r.rules }

type testClashDNSRouter struct {
	adapter.DNSRouter
	rules []adapter.DNSRule
}

func (r *testClashDNSRouter) Rules() []adapter.DNSRule { return r.rules }

func TestGetRulesIndexed(t *testing.T) {
	t.Parallel()
	first := &testClashRule{ruleType: "default", payload: "domain_suffix=example.com", proxy: "proxy", uuid: "u-1"}
	second := &testClashRule{ruleType: "default", payload: "geoip=cn", proxy: "direct", uuid: "u-2", disabled: true}
	router := &testClashRuleRouter{rules: []adapter.Rule{first, second}}
	dnsRouter := &testClashDNSRouter{}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	getRules(router, dnsRouter)(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	body := response.Body.String()
	require.Contains(t, body, `"index":0`)
	require.Contains(t, body, `"index":1`)
	require.Contains(t, body, `"payload":"domain_suffix=example.com"`)
	require.Contains(t, body, `"proxy":"proxy"`)
	require.Contains(t, body, `"size":-1`)
}

func TestDisableRulesByIndex(t *testing.T) {
	t.Parallel()
	first := &testClashRule{ruleType: "default", payload: "a", proxy: "proxy", uuid: "u-1"}
	second := &testClashRule{ruleType: "default", payload: "b", proxy: "direct", uuid: "u-2"}
	router := &testClashRuleRouter{rules: []adapter.Rule{first, second}}
	dnsRouter := &testClashDNSRouter{}

	request := httptest.NewRequest(http.MethodPatch, "/disable", strings.NewReader(`{"1":true,"9":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	render.Status(request, http.StatusOK)
	disableRules(router, dnsRouter)(response, request)

	require.Equal(t, http.StatusNoContent, response.Code)
	require.False(t, first.Disabled(), "index 0 must stay enabled")
	require.True(t, second.Disabled(), "index 1 must be disabled")

	request = httptest.NewRequest(http.MethodPatch, "/disable", strings.NewReader(`{"1":false}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	disableRules(router, dnsRouter)(response, request)
	require.Equal(t, http.StatusNoContent, response.Code)
	require.False(t, second.Disabled(), "index 1 must be re-enabled")
}
