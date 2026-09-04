// Package authz maps LDAP group names to permissions on S3 bucket namespaces.
package authz

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

const ctxRulesKey ctxKey = "rules"

const (
	// AllBucketsReadGroup is the reserved LDAP group that grants read access to
	// every bucket namespace.
	AllBucketsReadGroup = "s3gateway-all-r"
	// AllBucketsPrefix is the internal rule prefix used for all-bucket access.
	AllBucketsPrefix = "*"
)

// WithRules stores rules in the context.
func WithRules(ctx context.Context, rules []Rule) context.Context {
	return context.WithValue(ctx, ctxRulesKey, rules)
}

// RulesFromRequest retrieves the authorization rules stored in the request context.
func RulesFromRequest(r *http.Request) []Rule {
	v := r.Context().Value(ctxRulesKey)
	if v == nil {
		return nil
	}
	rules, _ := v.([]Rule)
	return rules
}

// Perm is a bitmask of operations granted on a bucket namespace. LDAP group
// suffixes use these permission letters:
//
//	r = read
//	w = upload objects and mutate object tags
//	c = create buckets and put bucket configuration or ACLs
//	d = delete object(s)
//	b = delete buckets and bucket configuration
type Perm uint32

const (
	// PermNone grants no operations.
	PermNone Perm = 0

	// PermRead grants read operations.
	PermRead Perm = 1 << iota
	// PermWrite grants object uploads and object-tag mutations.
	PermWrite
	// PermCreateBucket grants bucket creation and configuration writes.
	PermCreateBucket
	// PermDeleteObject grants object deletion.
	PermDeleteObject
	// PermDeleteBucket grants bucket and bucket-configuration deletion.
	PermDeleteBucket

	// PermReadWrite combines read with object-upload and object-tag permissions.
	PermReadWrite = PermRead | PermWrite
)

// Rule grants a permission mask to buckets in one namespace. A bucket's
// namespace is the lowercase portion before its first hyphen. AllBucketsPrefix
// is reserved for global read access.
type Rule struct {
	BucketPrefix string // e.g. "test"
	Perm         Perm
}

// RulesFromGroups parses authorization-shaped LDAP groups and merges all
// permissions that target the same namespace. Unrecognized groups are ignored.
func RulesFromGroups(groups map[string]struct{}) []Rule {
	byPrefix := map[string]Perm{}
	for g := range groups {
		prefix, perm, ok := ParseGroup(g)
		if !ok {
			continue
		}
		bp := strings.ToLower(prefix)
		byPrefix[bp] |= perm
	}
	out := make([]Rule, 0, len(byPrefix))
	for p, perm := range byPrefix {
		out = append(out, Rule{BucketPrefix: p, Perm: perm})
	}
	return out
}

// ParseGroup parses the reserved AllBucketsReadGroup or a case-insensitive
// "namespace-letters" group name. The supported permission letters are r, w,
// c, d, and b; any other letter makes the entire group invalid.
func ParseGroup(g string) (prefix string, perm Perm, ok bool) {
	g = strings.ToLower(strings.TrimSpace(g))
	if g == AllBucketsReadGroup {
		return AllBucketsPrefix, PermRead, true
	}
	i := strings.Index(g, "-")
	if i <= 0 || i >= len(g)-1 {
		return "", PermNone, false
	}
	p := strings.TrimSpace(g[:i])
	letters := strings.TrimSpace(g[i+1:])
	if p == "" || letters == "" {
		return "", PermNone, false
	}

	var out Perm
	for _, ch := range letters {
		switch ch {
		case 'r':
			out |= PermRead
		case 'w':
			out |= PermWrite
		case 'c':
			out |= PermCreateBucket
		case 'd':
			out |= PermDeleteObject
		case 'b':
			out |= PermDeleteBucket
		default:
			return "", PermNone, false
		}
	}
	if out == PermNone {
		return "", PermNone, false
	}
	return p, out, true
}

// BucketNamespace returns the namespace portion of a bucket name: everything
// before the first '-'. If the name contains no '-', the whole name is returned.
func BucketNamespace(bucket string) string {
	b := strings.ToLower(bucket)
	if i := strings.Index(b, "-"); i > 0 {
		return b[:i]
	}
	return b
}

// BucketPerm combines permissions for bucket's lowercase namespace with any
// global read rule. AllBucketsPrefix can grant only read access.
func BucketPerm(rules []Rule, bucket string) Perm {
	ns := BucketNamespace(bucket)
	var perm Perm
	for _, r := range rules {
		prefix := strings.ToLower(strings.TrimSpace(r.BucketPrefix))
		if prefix == AllBucketsPrefix {
			perm |= r.Perm & PermRead
			continue
		}
		if ns == prefix {
			perm |= r.Perm
		}
	}
	return perm
}

// CanRead reports whether rules grant read permission on bucket.
func CanRead(rules []Rule, bucket string) bool { return BucketPerm(rules, bucket)&PermRead != 0 }

// CanReadAll reports whether rules grant read permission to every bucket.
func CanReadAll(rules []Rule) bool {
	for _, r := range rules {
		if strings.TrimSpace(r.BucketPrefix) == AllBucketsPrefix && r.Perm&PermRead != 0 {
			return true
		}
	}
	return false
}

// CanWrite reports whether rules grant object-upload and object-tag permission
// on bucket.
func CanWrite(rules []Rule, bucket string) bool { return BucketPerm(rules, bucket)&PermWrite != 0 }

// CanConfigure reports whether rules grant bucket configuration or ACL writes
// in bucket's namespace.
func CanConfigure(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermCreateBucket != 0
}

// CanCreateBucket reports whether rules grant bucket creation in bucket's
// namespace.
func CanCreateBucket(rules []Rule, bucket string) bool {
	return CanConfigure(rules, bucket)
}

// CanDeleteObject reports whether rules grant object deletion on bucket.
func CanDeleteObject(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermDeleteObject != 0
}

// CanDeleteBucket reports whether rules grant deletion of a bucket or its
// configuration.
func CanDeleteBucket(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermDeleteBucket != 0
}
