package gateway

import (
	"net"
	"strings"
	"testing"
)

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
