package main

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestDecodeUserPassFromAccessKeyErrorPaths(t *testing.T) {
	t.Run("accessKey not base64", func(t *testing.T) {
		_, _, err := decodeUserPassFromAccessKey("!not-base64!")
		if err == nil {
			t.Fatalf("expected error for non-base64 access key")
		}
		if !strings.Contains(err.Error(), "accessKey not base64") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accessKey must decode to user pass", func(t *testing.T) {
		accessKey := base64.StdEncoding.EncodeToString([]byte("useronly"))
		_, _, err := decodeUserPassFromAccessKey(accessKey)
		if err == nil {
			t.Fatalf("expected error for decoded access key without AD:username:password format")
		}
		if !strings.Contains(err.Error(), "accessKey must decode to 'AD:username:password'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestFetchGroupsUPNLDAPBindFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_ = conn.Close()
	}()

	cfg := Config{
		LDAPURL:    "ldap://" + ln.Addr().String(),
		BaseDN:     "dc=example,dc=com",
		LDAPDomain: "example.com",
	}
	_, err = fetchGroupsUPN(cfg, "user", "wrongpass")
	if err == nil {
		t.Fatalf("expected ldap bind failure error")
	}
	if !strings.Contains(err.Error(), "ldap bind failed:") {
		t.Fatalf("unexpected error: %v", err)
	}

	<-done
}
