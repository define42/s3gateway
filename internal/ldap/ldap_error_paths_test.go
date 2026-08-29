package ldap

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/config"
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

	cfg := config.Config{
		LDAPURL:    "ldap://" + ln.Addr().String(),
		BaseDN:     "dc=example,dc=com",
		LDAPDomain: "example.com",
	}
	_, err = FetchGroupsUPN(cfg, "user", "wrongpass")
	if err == nil {
		t.Fatalf("expected ldap bind failure error")
	}
	if !strings.Contains(err.Error(), "ldap bind failed:") {
		t.Fatalf("unexpected error: %v", err)
	}

	<-done
}

func TestFetchGroupsUPNLDAPOperationTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})

	cfg := config.Config{
		LDAPURL:              "ldap://" + ln.Addr().String(),
		BaseDN:               "dc=example,dc=com",
		LDAPDomain:           "example.com",
		LDAPOperationTimeout: 50 * time.Millisecond,
	}
	started := time.Now()
	_, err = FetchGroupsUPN(cfg, "user", "password")
	if err == nil {
		t.Fatal("expected LDAP operation timeout")
	}
	if !strings.Contains(err.Error(), "ldap bind failed:") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("LDAP operation exceeded timeout budget: %s", elapsed)
	}
}
