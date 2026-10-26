package clashapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

// When name is composed of a partial escape string, Golang does not unescape it
func getEscapeParam(r *http.Request, paramName string) string {
	param := chi.URLParam(r, paramName)
	if newParam, err := url.PathUnescape(param); err == nil {
		param = newParam
	}
	return param
}

// routeOnEscapedPath keeps percent-encoded slashes inside a path segment.
//
// chi matches routes against r.URL.Path, which is already decoded, so a proxy
// tag containing a literal slash splits into extra segments and the route no
// longer matches. Proxy providers name their nodes "Provider/Node", which made
// every per-node endpoint (/proxies/{name}, /proxies/{name}/delay, PUT
// /proxies/{name}) answer 404 for essentially every node in a modern profile.
//
// Only requests that encode a slash are affected; everything else keeps the
// decoded path so static file serving and ordinary routes are untouched.
func routeOnEscapedPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath := r.URL.EscapedPath()
		if strings.Contains(strings.ToLower(escapedPath), "%2f") {
			r.URL.Path = escapedPath
		}
		next.ServeHTTP(w, r)
	})
}
