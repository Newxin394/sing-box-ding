package httpclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRequestAuthority(t *testing.T) {
	testCases := []struct {
		name   string
		url    string
		expect string
	}{
		{name: "https default port", url: "https://example.com/foo", expect: "example.com:443"},
		{name: "http default port", url: "http://example.com/foo", expect: "example.com:80"},
		{name: "https explicit port", url: "https://example.com:8443/foo", expect: "example.com:8443"},
		{name: "https uppercase host", url: "https://EXAMPLE.COM/foo", expect: "example.com:443"},
		{name: "https ipv6 default port", url: "https://[2001:db8::1]/foo", expect: "[2001:db8::1]:443"},
		{name: "https ipv6 explicit port", url: "https://[2001:db8::1]:8443/foo", expect: "[2001:db8::1]:8443"},
		{name: "https ipv4", url: "https://192.0.2.1/foo", expect: "192.0.2.1:443"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := url.Parse(testCase.url)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			got := requestAuthority(&http.Request{URL: parsed})
			if got != testCase.expect {
				t.Fatalf("got %q, want %q", got, testCase.expect)
			}
		})
	}
	t.Run("nil request", func(t *testing.T) {
		if got := requestAuthority(nil); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
	t.Run("nil URL", func(t *testing.T) {
		if got := requestAuthority(&http.Request{}); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
	t.Run("empty host", func(t *testing.T) {
		if got := requestAuthority(&http.Request{URL: &url.URL{Scheme: "https"}}); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}

func TestRequestReplayable(t *testing.T) {
	tests := []struct {
		name   string
		method string
		key    string
		want   bool
	}{
		{name: "get", method: http.MethodGet, want: true},
		{name: "head", method: http.MethodHead, want: true},
		{name: "post without idempotency key", method: http.MethodPost, want: false},
		{name: "put without idempotency key", method: http.MethodPut, want: false},
		{name: "post with idempotency key", method: http.MethodPost, key: "request-1", want: true},
		{name: "patch with alternate idempotency key", method: http.MethodPatch, key: "alternate-request-1", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, "https://example.com/", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			if test.key != "" {
				if test.method == http.MethodPatch {
					request.Header.Set("X-Idempotency-Key", test.key)
				} else {
					request.Header.Set("Idempotency-Key", test.key)
				}
			}
			if got := requestReplayable(request); got != test.want {
				t.Fatalf("requestReplayable() = %v, want %v", got, test.want)
			}
		})
	}
}
