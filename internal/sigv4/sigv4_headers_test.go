package sigv4

import (
	"strings"
	"testing"
)

func TestCompressSpaces(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty"},
		{name: "clean ASCII", value: "application/octet-stream", want: "application/octet-stream"},
		{name: "single spaces", value: "case-0123 item-0042", want: "case-0123 item-0042"},
		{name: "leading and trailing spaces", value: " a ", want: " a "},
		{name: "only spaces", value: "   ", want: " "},
		{name: "repeated spaces", value: "  a   b  ", want: " a b "},
		{name: "single tab", value: "a\tb", want: "a b"},
		{name: "mixed whitespace", value: "\t a\t \tb \t", want: " a b "},
		{name: "other ASCII unchanged", value: "\x00a\r\nb\x7f", want: "\x00a\r\nb\x7f"},
		{name: "Unicode", value: "café 中 🙂", want: "café 中 🙂"},
		{name: "Unicode with whitespace", value: "café  中\t🙂", want: "café 中 🙂"},
		{name: "nonbreaking spaces", value: "\u00a0a\u00a0", want: "\u00a0a\u00a0"},
		{name: "replacement rune", value: "\ufffda\ufffd", want: "\ufffda\ufffd"},
		{name: "invalid byte", value: "a\xffb", want: "a\ufffdb"},
		{name: "consecutive invalid bytes", value: "\xff\xfe", want: "\ufffd\ufffd"},
		{name: "truncated UTF8", value: "\xe2\x82", want: "\ufffd\ufffd"},
		{name: "overlong UTF8", value: "\xc0\xaf", want: "\ufffd\ufffd"},
		{name: "invalid UTF8 with whitespace", value: "a\xff  b\t\xfe", want: "a\ufffd b \ufffd"},
		{name: "late tab", value: strings.Repeat("a", 512) + "\tb", want: strings.Repeat("a", 512) + " b"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := compressSpaces(tt.value); got != tt.want {
				t.Fatalf("compressSpaces(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func FuzzCompressSpaces(f *testing.F) {
	for _, value := range []string{
		"", "application/octet-stream", "a b", "  a\t \tb  ",
		"café  中\t🙂", "\u00a0a\u00a0", "a\xff\xfe  b\t\xe2\x82",
	} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 16<<10 {
			t.Skip("bound normalization reference work")
		}
		// Rune conversion independently specifies invalid UTF-8 replacement.
		// Repeated substitution collapses only ASCII spaces and tabs while
		// retaining a single leading or trailing space.
		want := strings.ReplaceAll(string([]rune(value)), "\t", " ")
		for strings.Contains(want, "  ") {
			want = strings.ReplaceAll(want, "  ", " ")
		}
		if got := compressSpaces(value); got != want {
			t.Fatalf("compressSpaces(%q) = %q, want %q", value, got, want)
		}
	})
}
