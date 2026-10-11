package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter(router adapter.Router, dnsRouter adapter.DNSRouter) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules(router, dnsRouter))
	r.Patch("/disable", disableRules(router, dnsRouter))
	r.Route("/{uuid}", func(r chi.Router) {
		r.Use(parseRuleUUID, findRuleByUUID(router, dnsRouter))
		r.Put("/", changeRuleStatus)
	})
	return r
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`

	Disabled bool   `json:"disabled,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

// allRules returns route rules first and DNS rules second. The resulting
// position is the stable rule index used by mihomo-compatible clients.
func allRules(router adapter.Router, dnsRouter adapter.DNSRouter) []adapter.Rule {
	routeRules := router.Rules()
	dnsRules := dnsRouter.Rules()
	rules := make([]adapter.Rule, 0, len(routeRules)+len(dnsRules))
	rules = append(rules, routeRules...)
	for _, rule := range dnsRules {
		rules = append(rules, adapter.Rule(rule))
	}
	return rules
}

func getRules(router adapter.Router, dnsRouter adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		rawRules := allRules(router, dnsRouter)
		rules := make([]Rule, 0, len(rawRules))
		for index, rule := range rawRules {
			rules = append(rules, Rule{
				Index:    index,
				Type:     rule.Type(),
				Payload:  rule.String(),
				Proxy:    rule.Action().String(),
				Size:     -1,
				Disabled: rule.Disabled(),
				UUID:     rule.UUID(),
			})
		}
		render.JSON(w, r, render.M{
			"rules": rules,
		})
	}
}

// disableRules implements mihomo PATCH /rules/disable. The request body maps
// rule indexes to the wanted disabled state; out-of-range indexes are ignored.
func disableRules(router adapter.Router, dnsRouter adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload map[int]bool
		if err := render.DecodeJSON(r.Body, &payload); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if len(payload) != 0 {
			rules := allRules(router, dnsRouter)
			for index, disabled := range payload {
				if index < 0 || index >= len(rules) {
					continue
				}
				rules[index].SetDisabled(disabled)
			}
		}
		render.NoContent(w, r)
	}
}

func parseRuleUUID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uuid := getEscapeParam(r, "uuid")
		ctx := context.WithValue(r.Context(), CtxKeyRuleUUID, uuid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findRuleByUUID(router adapter.Router, dnsRouter adapter.DNSRouter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uuid := r.Context().Value(CtxKeyRuleUUID).(string)
			routeRule, exist := router.Rule(uuid)
			if exist {
				ctx := context.WithValue(r.Context(), CtxKeyRule, routeRule)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			dnsRule, dnsExist := dnsRouter.Rule(uuid)
			if dnsExist {
				ctx := context.WithValue(r.Context(), CtxKeyRule, adapter.Rule(dnsRule))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
		})
	}
}

func changeRuleStatus(w http.ResponseWriter, r *http.Request) {
	rule := r.Context().Value(CtxKeyRule).(adapter.Rule)
	rule.ChangeStatus()
	render.NoContent(w, r)
}
