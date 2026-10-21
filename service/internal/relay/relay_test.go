package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type nopLogger struct{}

func (nopLogger) Error(args ...any) {}

func TestIsHopByHopHeader(t *testing.T) {
	for header, expected := range map[string]bool{
		"Connection":        true,
		"connection":        true,
		"Keep-Alive":        true,
		"Transfer-Encoding": true,
		"Host":              true,
		"Content-Type":      false,
		"Authorization":     false,
		"X-Custom":          false,
	} {
		if IsHopByHopHeader(header) != expected {
			t.Errorf("IsHopByHopHeader(%q) = %v, want %v", header, IsHopByHopHeader(header), expected)
		}
	}
}

func TestParseInt64Header(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Reset", " 1729511400 ")
	if value, ok := ParseInt64Header(headers, "X-Reset"); !ok || value != 1729511400 {
		t.Errorf("got %d, %v", value, ok)
	}
	headers.Set("X-Invalid", "not-a-number")
	if _, ok := ParseInt64Header(headers, "X-Invalid"); ok {
		t.Error("invalid value should not parse")
	}
	if _, ok := ParseInt64Header(headers, "X-Missing"); ok {
		t.Error("missing header should not parse")
	}
}

func TestCopyRequestHeadersSkipsHopByHopAndAuthorization(t *testing.T) {
	source := http.Header{}
	source.Set("Content-Type", "application/json")
	source.Set("Connection", "keep-alive")
	source.Set("Authorization", "Bearer client-token")
	request, _ := http.NewRequest(http.MethodPost, "https://example.invalid", nil)
	CopyRequestHeaders(request, source)
	if request.Header.Get("Content-Type") != "application/json" {
		t.Error("content type not copied")
	}
	if request.Header.Get("Connection") != "" {
		t.Error("hop-by-hop header copied")
	}
	if request.Header.Get("Authorization") != "" {
		t.Error("authorization copied")
	}
}

func TestApplyServiceHeadersOverrides(t *testing.T) {
	serviceHeaders := http.Header{}
	serviceHeaders.Set("User-Agent", "custom-agent")
	request, _ := http.NewRequest(http.MethodPost, "https://example.invalid", nil)
	request.Header.Set("User-Agent", "original")
	request.Header.Add("Accept-Encoding", "gzip")
	ApplyServiceHeaders(request, serviceHeaders)
	if request.Header.Get("User-Agent") != "custom-agent" {
		t.Error("service header not applied")
	}
	if len(request.Header.Values("Accept-Encoding")) != 1 {
		t.Error("unrelated header modified")
	}
}

func TestCopyResponseHeadersSkipsHopByHop(t *testing.T) {
	source := http.Header{}
	source.Set("Content-Type", "text/event-stream")
	source.Set("Transfer-Encoding", "chunked")
	destination := http.Header{}
	CopyResponseHeaders(destination, source)
	if destination.Get("Content-Type") != "text/event-stream" {
		t.Error("content type not copied")
	}
	if destination.Get("Transfer-Encoding") != "" {
		t.Error("hop-by-hop header copied")
	}
}

func TestWriteUntrackedResponseCopiesBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	response := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	WriteUntrackedResponse(nopLogger{}, recorder, response)
	if recorder.Body.String() != `{"ok":true}` {
		t.Errorf("body = %q", recorder.Body.String())
	}
}

func TestWriteUntrackedResponseStreamsSSE(t *testing.T) {
	recorder := httptest.NewRecorder()
	response := &http.Response{
		Header: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:   io.NopCloser(strings.NewReader("data: one\n\ndata: two\n\n")),
	}
	WriteUntrackedResponse(nopLogger{}, recorder, response)
	if recorder.Body.String() != "data: one\n\ndata: two\n\n" {
		t.Errorf("body = %q", recorder.Body.String())
	}
	if !recorder.Flushed {
		t.Error("expected flushes during streaming")
	}
}
