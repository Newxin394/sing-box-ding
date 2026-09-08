package provider

import (
	"strings"
	"testing"
)

func TestReadProviderLocalContentLimitsSize(t *testing.T) {
	const limit = 8
	testCases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "exact limit is accepted",
			body: strings.Repeat("x", limit),
			want: strings.Repeat("x", limit),
		},
		{
			name: "oversized content is rejected",
			body: strings.Repeat("x", limit+1),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			content, err := readProviderLocalContentWithLimit(strings.NewReader(testCase.body), limit)
			if testCase.want == "" {
				if err == nil {
					t.Fatal("expected oversized content to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(content) != testCase.want {
				t.Fatalf("got %q, want %q", content, testCase.want)
			}
		})
	}
}
