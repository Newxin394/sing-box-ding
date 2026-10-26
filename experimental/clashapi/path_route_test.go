package clashapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

// TestRouteOnEscapedPathKeepsSlashInSegment covers the shape every proxy
// provider produces: "Provider/Node". Routing on the decoded path splits that
// into two segments, so /proxies/{name}/delay answered 404 for the vast
// majority of nodes and the delay test could never run.
func TestRouteOnEscapedPathKeepsSlashInSegment(t *testing.T) {
	router := chi.NewRouter()
	router.Use(routeOnEscapedPath)

	var captured string
	router.Get("/proxies/{name}/delay", func(writer http.ResponseWriter, request *http.Request) {
		captured = getEscapeParam(request, "name")
		writer.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(router)
	defer server.Close()

	proxyName := "家宽/cn-xin1"
	response, err := http.Get(server.URL + "/proxies/" + url.PathEscape(proxyName) + "/delay")
	require.NoError(t, err)
	defer response.Body.Close()

	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.Equal(t, proxyName, captured)
}

// TestRouteOnEscapedPathLeavesPlainPathsAlone guards the blast radius: the
// rewrite must only apply when a slash is percent-encoded.
func TestRouteOnEscapedPathLeavesPlainPathsAlone(t *testing.T) {
	router := chi.NewRouter()
	router.Use(routeOnEscapedPath)

	var seenPath string
	router.Get("/proxies/{name}", func(writer http.ResponseWriter, request *http.Request) {
		seenPath = request.URL.Path
		writer.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(router)
	defer server.Close()

	proxyName := "家宽 上海"
	response, err := http.Get(server.URL + "/proxies/" + url.PathEscape(proxyName))
	require.NoError(t, err)
	defer response.Body.Close()

	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.Equal(t, "/proxies/"+proxyName, seenPath)
}
