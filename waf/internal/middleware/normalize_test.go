package middleware

import (
	"testing"

	"go.uber.org/zap"
)

func TestNormalizeString(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	tests := []struct {
		name      string
		input     string
		maxPasses int
		expected  string
	}{
		{
			name:      "single URL encoding",
			input:     "%3Cscript%3E",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "double URL encoding",
			input:     "%253Cscript%253E",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "double encoded single quote",
			input:     "%2527",
			maxPasses: 3,
			expected:  "'",
		},
		{
			name:      "decode limit with nested quote payload max 3",
			input:     "%252527",
			maxPasses: 3,
			expected:  "'",
		},
		{
			name:      "decode limit with nested quote payload max 2",
			input:     "%252527",
			maxPasses: 2,
			expected:  "%27",
		},
		{
			name:      "html named entities",
			input:     "&lt;script&gt;",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "html decimal entities",
			input:     "&#60;script&#62;",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "html hex entities",
			input:     "&#x3c;script&#x3e;",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "mixed case to lower",
			input:     "<SCRIPT>",
			maxPasses: 3,
			expected:  "<script>",
		},
		{
			name:      "strip null byte",
			input:     "test\x00value",
			maxPasses: 3,
			expected:  "testvalue",
		},
		{
			name:      "url decode plus lowercase",
			input:     "UNION%20SELECT",
			maxPasses: 3,
			expected:  "union select",
		},
		{
			name:      "url decode plus null byte strip",
			input:     "%3Cscr%00ipt%3E",
			maxPasses: 3,
			expected:  "<script>",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeString(tc.input, tc.maxPasses, logger)
			if got != tc.expected {
				t.Fatalf("normalizeString(%q, %d) = %q, want %q", tc.input, tc.maxPasses, got, tc.expected)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	tests := []struct {
		name      string
		input     string
		maxPasses int
		expected  string
	}{
		{
			name:      "parent traversal collapse",
			input:     "/admin/../etc/passwd",
			maxPasses: 3,
			expected:  "/etc/passwd",
		},
		{
			name:      "dot segments collapse",
			input:     "/./admin/./config",
			maxPasses: 3,
			expected:  "/admin/config",
		},
		{
			name:      "duplicate slashes collapse",
			input:     "//admin///config",
			maxPasses: 3,
			expected:  "/admin/config",
		},
		{
			name:      "encoded traversal",
			input:     "/admin%2F..%2Fetc%2Fpasswd",
			maxPasses: 3,
			expected:  "/etc/passwd",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := normalizePath(tc.input, tc.maxPasses, logger)
			if got != tc.expected {
				t.Fatalf("normalizePath(%q, %d) = %q, want %q", tc.input, tc.maxPasses, got, tc.expected)
			}
		})
	}
}

func TestDecodeURLMultiPass(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	tests := []struct {
		name      string
		input     string
		maxPasses int
		expected  string
	}{
		{
			name:      "plain text unchanged",
			input:     "hello",
			maxPasses: 3,
			expected:  "hello",
		},
		{
			name:      "single pass decode",
			input:     "%48ello",
			maxPasses: 3,
			expected:  "Hello",
		},
		{
			name:      "two pass decode",
			input:     "%2548ello",
			maxPasses: 3,
			expected:  "Hello",
		},
		{
			name:      "decode limit",
			input:     "%2548ello",
			maxPasses: 1,
			expected:  "%48ello",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := decodeURLMultiPass(tc.input, tc.maxPasses, logger)
			if got != tc.expected {
				t.Fatalf("decodeURLMultiPass(%q, %d) = %q, want %q", tc.input, tc.maxPasses, got, tc.expected)
			}
		})
	}
}
