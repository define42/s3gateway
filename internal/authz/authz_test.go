package authz

import (
	"testing"
)

func TestBucketPerm_MostSpecificPrefix(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "team-", Perm: PermRead},
		{BucketPrefix: "team2-", Perm: PermReadWrite},
	}

	tests := []struct {
		bucket string
		want   Perm
	}{
		// Matches only "team-" (longest matching prefix; "team2-" doesn't match)
		{"team-data", PermRead},
		// Matches both "team-" and "team2-"; "team2-" is more specific, so only its perm applies
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
	// Verify that the old OR-union behaviour is gone: a bucket matching a less-specific
	// prefix must NOT inherit permissions from that less-specific rule when a more-specific
	// rule also matches.
	rules := []Rule{
		{BucketPrefix: "team-", Perm: PermDeleteBucket},
		{BucketPrefix: "team2-", Perm: PermRead},
	}

	got := BucketPerm(rules, "team2-logs")
	if got&PermDeleteBucket != 0 {
		t.Errorf("BucketPerm(team2-logs) unexpectedly contains PermDeleteBucket from less-specific prefix")
	}
	if got != PermRead {
		t.Errorf("BucketPerm(team2-logs) = %v, want PermRead", got)
	}
}

func TestBucketPerm_ExactSingleMatch(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "alpha-", Perm: PermWrite},
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

func TestBucketPerm_CaseInsensitive(t *testing.T) {
	rules := []Rule{
		{BucketPrefix: "team-", Perm: PermRead},
	}
	if got := BucketPerm(rules, "TEAM-data"); got != PermRead {
		t.Errorf("BucketPerm(TEAM-data) = %v, want PermRead", got)
	}
}
