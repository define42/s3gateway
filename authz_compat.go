package main

import "github.com/define42/s3gateway/internal/auth"

type Perm = auth.Perm

type Rule = auth.Rule

const (
	PermNone         = auth.PermNone
	PermRead         = auth.PermRead
	PermWrite        = auth.PermWrite
	PermCreateBucket = auth.PermCreateBucket
	PermDeleteObject = auth.PermDeleteObject
	PermDeleteBucket = auth.PermDeleteBucket
	PermReadWrite    = auth.PermReadWrite
)

func rulesFromGroups(groups map[string]struct{}) []Rule {
	return auth.RulesFromGroups(groups)
}

func parseGroup(g string) (prefix string, perm Perm, ok bool) {
	return auth.ParseGroup(g)
}

func canRead(rules []Rule, bucket string) bool {
	return auth.CanRead(rules, bucket)
}

func canWrite(rules []Rule, bucket string) bool {
	return auth.CanWrite(rules, bucket)
}

func canCreateBucket(rules []Rule, bucket string) bool {
	return auth.CanCreateBucket(rules, bucket)
}

func canDeleteObject(rules []Rule, bucket string) bool {
	return auth.CanDeleteObject(rules, bucket)
}

func canDeleteBucket(rules []Rule, bucket string) bool {
	return auth.CanDeleteBucket(rules, bucket)
}

func bucketPerm(rules []Rule, bucket string) Perm {
	return auth.BucketPerm(rules, bucket)
}
