// Package s3credentials encodes LDAP credentials as S3 access keys and derives
// the matching S3 signing secret.
//
// X25519 access keys encrypt the username and password for a configured
// gateway private key. The package also decodes the legacy AD-prefixed Base64
// format for compatibility.
package s3credentials
