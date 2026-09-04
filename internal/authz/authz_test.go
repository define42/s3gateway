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
		{"hello-data-2024", true}, // namespace "hello" → match
		{"hello", true},           // no dash → whole name is namespace "hello" → match
		{"hello-2024", true},      // namespace "hello" → match
		{"hello2-data", false},    // namespace "hello2" → no match
		{"other-bucket", false},   // namespace "other" → no match
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

func TestAllBucketsReadGroup(t *testing.T) {
	tests := []struct {
		name  string
		group string
	}{
		{name: "exact", group: AllBucketsReadGroup},
		{name: "case insensitive and trimmed", group: "  S3GATEWAY-ALL-R  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, perm, ok := ParseGroup(tt.group)
			if !ok || prefix != AllBucketsPrefix || perm != PermRead {
				t.Fatalf(
					"ParseGroup(%q) = %q, %v, %t; want %q, %v, true",
					tt.group,
					prefix,
					perm,
					ok,
					AllBucketsPrefix,
					PermRead,
				)
			}
		})
	}

	rules := RulesFromGroups(map[string]struct{}{
		AllBucketsReadGroup: {},
		"team2-w":           {},
	})
	if !CanReadAll(rules) {
		t.Fatal("all-buckets read group did not grant global read access")
	}
	if CanReadAll(RulesFromGroups(map[string]struct{}{"team2-r": {}})) {
		t.Fatal("namespace read group unexpectedly granted global read access")
	}
	if _, _, ok := ParseGroup("s3gateway-all-rw"); ok {
		t.Fatal("non-reserved all-buckets group was accepted")
	}
	for _, bucket := range []string{"team2-data", "other-documents", "standalone"} {
		if !CanRead(rules, bucket) {
			t.Errorf("all-buckets read group did not grant read access to %q", bucket)
		}
	}
	if !CanWrite(rules, "team2-data") {
		t.Fatal("namespace write permission was not combined with global read")
	}
	if CanWrite(rules, "other-documents") ||
		CanCreateBucket(rules, "other-documents") ||
		CanDeleteObject(rules, "other-documents") ||
		CanDeleteBucket(rules, "other-documents") {
		t.Fatal("all-buckets read group granted a mutating permission")
	}
}

func TestAllBucketsPrefixCannotGrantMutatingPermissions(t *testing.T) {
	rules := []Rule{{
		BucketPrefix: AllBucketsPrefix,
		Perm: PermRead | PermWrite | PermCreateBucket |
			PermDeleteObject | PermDeleteBucket,
	}}

	if !CanReadAll(rules) || !CanRead(rules, "any-bucket") {
		t.Fatal("all-buckets prefix did not grant read access")
	}
	if CanWrite(rules, "any-bucket") ||
		CanCreateBucket(rules, "any-bucket") ||
		CanDeleteObject(rules, "any-bucket") ||
		CanDeleteBucket(rules, "any-bucket") {
		t.Fatal("all-buckets prefix granted a mutating permission")
	}
}
