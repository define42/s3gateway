package authz

import "strings"

// ==================== AuthZ: <prefix>-<letters> => bucket prefix "<prefix>-" ====================
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
	BucketPrefix string // e.g. "test-"
	Perm         Perm
}

func RulesFromGroups(groups map[string]struct{}) []Rule {
	byPrefix := map[string]Perm{}
	for g := range groups {
		prefix, perm, ok := ParseGroup(g)
		if !ok {
			continue
		}
		bp := strings.ToLower(prefix) + "-"
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
	i := strings.LastIndex(g, "-")
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

func BucketPerm(rules []Rule, bucket string) Perm {
	b := strings.ToLower(bucket)
	best := PermNone
	for _, r := range rules {
		if strings.HasPrefix(b, r.BucketPrefix) {
			best |= r.Perm
		}
	}
	return best
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
