package authz

import (
	"testing"
)

func TestBucketNamespace(t *testing.T) {
	tests := []struct {
		bucket string
		want   string
	}{
		{"team2-data", "team2"},
		{"team2-data-extra", "team2"},
		{"nohyphen", "nohyphen"},
		{"TEAM-data", "team"},
		{"-leading", "-leading"}, // leading dash: Index returns 0, not > 0, whole name
	}
	for _, tt := range tests {
		got := BucketNamespace(tt.bucket)
		if got != tt.want {
			t.Errorf("BucketNamespace(%q) = %q, want %q", tt.bucket, got, tt.want)
		}
	}
}

func TestBucketPerm_ExactNamespaceMatch(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "team", Perm: PermRead},
		{BucketPrefix: "team2", Perm: PermReadWrite},
	}

	tests := []struct {
		bucket string
		want   Perm
	}{
		// Namespace "team" matches exactly
		{"team-data", PermRead},
		// Namespace "team2" matches exactly; "team" does NOT match
		{"team2-data", PermReadWrite},
		// No match
		{"other-bucket", PermNone},
	}

	for _, tt := range tests {
		got := BucketPerm(rules, tt.bucket)
		if got != tt.want {
			t.Errorf("BucketPerm(%q) = %v, want %v", tt.bucket, got, tt.want)
		}
	}
}

func TestBucketPerm_NoOverlapUnion(t *testing.T) {
	// The namespace of "team2-logs" is "team2", which does not equal "team".
	// PermDeleteBucket from the "team" rule must NOT apply.
	rules := []Rule{
		{BucketPrefix: "team", Perm: PermDeleteBucket},
		{BucketPrefix: "team2", Perm: PermRead},
	}

	got := BucketPerm(rules, "team2-logs")
	if got&PermDeleteBucket != 0 {
		t.Errorf("BucketPerm(team2-logs) unexpectedly contains PermDeleteBucket from unrelated namespace")
	}
	if got != PermRead {
		t.Errorf("BucketPerm(team2-logs) = %v, want PermRead", got)
	}
}

func TestBucketPerm_ExactSingleMatch(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "alpha", Perm: PermWrite},
	}
	if got := BucketPerm(rules, "alpha-bucket"); got != PermWrite {
		t.Errorf("BucketPerm(alpha-bucket) = %v, want PermWrite", got)
	}
	if got := BucketPerm(rules, "beta-bucket"); got != PermNone {
		t.Errorf("BucketPerm(beta-bucket) = %v, want PermNone", got)
	}
}

func TestBucketPerm_EmptyRules(t *testing.T) {
	if got := BucketPerm(nil, "any-bucket"); got != PermNone {
		t.Errorf("BucketPerm with nil rules = %v, want PermNone", got)
	}
}

func TestHelloGroupReadAccess(t *testing.T) {
	// Group "hello-r": first '-' separates namespace "hello" from letter "r".
	rules := RulesFromGroups(map[string]struct{}{"hello-r": {}})

	buckets := []struct {
		name string
		want bool
	}{
		{"hello-data-2024", true},  // namespace "hello" → match
		{"hello", true},            // no dash → whole name is namespace "hello" → match
		{"hello-2024", true},       // namespace "hello" → match
		{"hello2-data", false},     // namespace "hello2" → no match
		{"other-bucket", false},    // namespace "other" → no match
	}

	for _, tt := range buckets {
		got := CanRead(rules, tt.name)
		if got != tt.want {
			t.Errorf("CanRead(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestBucketPerm_CaseInsensitive(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "team", Perm: PermRead},
		{BucketPrefix: "team2", Perm: PermReadWrite},
	}
	if got := BucketPerm(rules, "TEAM-data"); got != PermRead {
		t.Errorf("BucketPerm(TEAM-data) = %v, want PermRead", got)
	}
	if got := BucketPerm(rules, "TEAM2-data"); got != PermReadWrite {
		t.Errorf("BucketPerm(TEAM2-data) = %v, want PermReadWrite", got)
	}
}
