package ldap

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/authn"
	"github.com/define42/s3gateway/internal/config"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestWrapBindErrorClassifiesCredentialRejection(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantRejected bool
	}{
		{
			name:         "invalid credentials",
			err:          ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")),
			wantRejected: true,
		},
		{
			name: "network failure",
			err:  ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapBindError(tt.err)
			if got := errors.Is(err, authn.ErrRejectedCredentials); got != tt.wantRejected {
				t.Fatalf("rejection classification = %t, want %t: %v", got, tt.wantRejected, err)
			}
		})
	}
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
