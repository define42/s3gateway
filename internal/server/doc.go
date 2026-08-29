// Package server implements the authenticated, path-style S3 gateway HTTP
// handler.
//
// The gateway verifies SigV4 requests, maps LDAP groups to bucket-namespace
// permissions, forwards supported operations through an AWS SDK client, and
// exposes health, browser-administration, and Kafka pop endpoints.
package server
