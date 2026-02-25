package main

import authz "github.com/define42/s3gateway/internal/authz"

type Perm = authz.Perm
type Rule = authz.Rule

const (
PermNone         = authz.PermNone
PermRead         = authz.PermRead
PermWrite        = authz.PermWrite
PermCreateBucket = authz.PermCreateBucket
PermDeleteObject = authz.PermDeleteObject
PermDeleteBucket = authz.PermDeleteBucket
PermReadWrite    = authz.PermReadWrite
)

func rulesFromGroups(groups map[string]struct{}) []Rule { return authz.RulesFromGroups(groups) }
func parseGroup(g string) (string, Perm, bool)          { return authz.ParseGroup(g) }
func bucketPerm(rules []Rule, bucket string) Perm       { return authz.BucketPerm(rules, bucket) }
func canRead(rules []Rule, bucket string) bool          { return authz.CanRead(rules, bucket) }
func canWrite(rules []Rule, bucket string) bool         { return authz.CanWrite(rules, bucket) }
func canCreateBucket(rules []Rule, bucket string) bool  { return authz.CanCreateBucket(rules, bucket) }
func canDeleteObject(rules []Rule, bucket string) bool  { return authz.CanDeleteObject(rules, bucket) }
func canDeleteBucket(rules []Rule, bucket string) bool  { return authz.CanDeleteBucket(rules, bucket) }
