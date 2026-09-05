//go:build integration

package ldap_test

import (
	"context"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
	ldapinternal "github.com/define42/s3gateway/internal/ldap"
	"github.com/define42/s3gateway/internal/testutil"
)

func TestFetchGroupsUPNTrustedContainer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	fixture := testutil.WriteGatewayGlauthConfigWithAllBucketsRead(t)
	ldapURL, stop := testutil.StartGlauthWithConfig(ctx, t, fixture, "ldap")
	t.Cleanup(stop)
	tests := []struct {
		name    string
		base    string
		allowed bool
	}{
		{name: "direct group container", base: "ou=groups,dc=glauth,dc=com", allowed: true},
		{name: "case insensitive container", base: "OU=GROUPS,DC=GLAUTH,DC=COM", allowed: true},
		{name: "other container", base: "ou=protected,dc=glauth,dc=com"},
		{name: "ancestor does not trust descendants", base: "dc=glauth,dc=com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				LDAPURL:         ldapURL,
				LDAPDomain:      "example.com",
				BaseDN:          "dc=glauth,dc=com",
				LDAPGroupBaseDN: tt.base,
			}
			groups, err := ldapinternal.FetchGroupsUPN(cfg, "testuser", "dogood")
			if err != nil {
				t.Fatal(err)
			}
			rules := authz.RulesFromGroups(groups)
			if authz.CanWrite(rules, "team2-data") != tt.allowed || authz.CanReadAll(rules) != tt.allowed {
				t.Fatalf("container %q: allowed=%t, got groups %v", tt.base, tt.allowed, groups)
			}
			if !tt.allowed && len(groups) != 0 {
				t.Fatalf("untrusted container returned groups: %v", groups)
			}
		})
	}
}
