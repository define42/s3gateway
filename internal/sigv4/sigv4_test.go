package sigv4_test

import (
	"testing"

	"github.com/define42/s3gateway/internal/sigv4"
)

func TestCanonicalURI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "", expected: "/"},
		{input: "bucket/key", expected: "/bucket/key"},
		{input: "/already/escaped", expected: "/already/escaped"},
	}

	for _, test := range tests {
		if got := sigv4.CanonicalURI(test.input); got != test.expected {
			t.Fatalf("CanonicalURI(%q) = %q, want %q", test.input, got, test.expected)
		}
	}
}
