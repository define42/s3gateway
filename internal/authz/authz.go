package authz

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

const ctxRulesKey ctxKey = "rules"

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

// ==================== AuthZ: <namespace>-<letters> => bucket namespace "<namespace>" ====================
// Permission letters:
//
//	r = read
//	w = write
//	c = create bucket
//	d = delete object(s)
//	b = delete bucket
type Perm uint32

const (
	PermNone Perm = 0

	PermRead Perm = 1 << iota
	PermWrite
	PermCreateBucket
	PermDeleteObject
	PermDeleteBucket

	PermReadWrite = PermRead | PermWrite
)

type Rule struct {
	BucketPrefix string // e.g. "test"
	Perm         Perm
}

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

func ParseGroup(g string) (prefix string, perm Perm, ok bool) {
	g = strings.ToLower(strings.TrimSpace(g))
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

func BucketPerm(rules []Rule, bucket string) Perm {
	ns := BucketNamespace(bucket)
	for _, r := range rules {
		if ns == r.BucketPrefix {
			return r.Perm
		}
	}
	return PermNone
}

func CanRead(rules []Rule, bucket string) bool  { return BucketPerm(rules, bucket)&PermRead != 0 }
func CanWrite(rules []Rule, bucket string) bool { return BucketPerm(rules, bucket)&PermWrite != 0 }
func CanCreateBucket(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermCreateBucket != 0
}
func CanDeleteObject(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermDeleteObject != 0
}
func CanDeleteBucket(rules []Rule, bucket string) bool {
	return BucketPerm(rules, bucket)&PermDeleteBucket != 0
}
