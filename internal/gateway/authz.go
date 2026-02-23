package gateway

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

func rulesFromGroups(groups map[string]struct{}) []Rule {
	byPrefix := map[string]Perm{}
	for g := range groups {
		prefix, perm, ok := parseGroup(g)
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

func parseGroup(g string) (prefix string, perm Perm, ok bool) {
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

func bucketPerm(rules []Rule, bucket string) Perm {
	b := strings.ToLower(bucket)
	best := PermNone
	for _, r := range rules {
		if strings.HasPrefix(b, r.BucketPrefix) {
			best |= r.Perm
		}
	}
	return best
}

func canRead(rules []Rule, bucket string) bool  { return bucketPerm(rules, bucket)&PermRead != 0 }
func canWrite(rules []Rule, bucket string) bool { return bucketPerm(rules, bucket)&PermWrite != 0 }
func canCreateBucket(rules []Rule, bucket string) bool {
	return bucketPerm(rules, bucket)&PermCreateBucket != 0
}
func canDeleteObject(rules []Rule, bucket string) bool {
	return bucketPerm(rules, bucket)&PermDeleteObject != 0
}
func canDeleteBucket(rules []Rule, bucket string) bool {
	return bucketPerm(rules, bucket)&PermDeleteBucket != 0
}

