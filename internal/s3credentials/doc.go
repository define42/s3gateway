// Package s3credentials encodes LDAP credentials as S3 access keys and derives
// the matching S3 signing secret.
//
// X25519 access keys encrypt the username and password for a configured
// gateway private key.
package s3credentials
