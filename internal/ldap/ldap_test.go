package ldap

import (
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestFetchGroupsUPNRejectsInvalidGroupContainer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		base string
	}{
		{name: "missing"},
		{name: "blank", base: " \t "},
		{name: "malformed", base: "not-a-dn"},
		{name: "empty attribute", base: "ou=,dc=example,dc=com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Config{LDAPGroupBaseDN: tt.base}
			groups, err := FetchGroupsUPN(cfg, "user", "password")
			if err == nil || !strings.Contains(err.Error(), "LDAP_GROUP_BASE_DN") {
				t.Fatalf("expected group-container error before dialing LDAP, got %v", err)
			}
			if len(groups) != 0 {
				t.Fatalf("invalid container returned groups: %v", groups)
			}
		})
	}
}

func TestTrustedGroupCN(t *testing.T) {
	t.Parallel()
	const base = "OU=S3GatewayGroups,DC=example,DC=com"
	tests := []struct {
		name string
		base string
		dn   string
		want string
	}{
		{name: "trusted namespace", dn: "CN=finance-rwcdb," + base, want: "finance-rwcdb"},
		{name: "trusted global read", dn: "CN=s3gateway-all-r," + base, want: "s3gateway-all-r"},
		{name: "case insensitive parent", dn: "cn=finance-r,ou=s3gatewaygroups,dc=EXAMPLE,dc=COM", want: "finance-r"},
		{name: "spaces after separators", dn: "CN=finance-r, OU=S3GatewayGroups, DC=example, DC=com", want: "finance-r"},
		{name: "escaped CN", dn: `CN=finance\2dr,` + base, want: "finance-r"},
		{name: "escaped container", base: `OU=S3\,Gateway,DC=example,DC=com`, dn: `CN=finance-r,OU=S3\2cGateway,DC=example,DC=com`, want: "finance-r"},
		{name: "duplicate CN outside container", dn: "CN=finance-rwcdb,OU=DelegatedTeam,DC=example,DC=com"},
		{name: "global group outside container", dn: "CN=s3gateway-all-r,OU=DelegatedTeam,DC=example,DC=com"},
		{name: "nested group", dn: "CN=finance-r,OU=DelegatedTeam," + base},
		{name: "nested global group", dn: "CN=s3gateway-all-r,OU=DelegatedTeam," + base},
		{name: "container itself", dn: base},
		{name: "wrong domain", dn: "CN=finance-r,OU=S3GatewayGroups,DC=other,DC=com"},
		{name: "lookalike container", dn: "CN=finance-r,OU=UntrustedS3GatewayGroups,DC=example,DC=com"},
		{name: "escaped separator spoof", dn: `CN=finance-r,OU=Delegated\,OU=S3GatewayGroups,DC=example,DC=com`},
		{name: "extra parent attribute", dn: "CN=finance-r,OU=S3GatewayGroups+OU=Delegated,DC=example,DC=com"},
		{name: "multi-valued leaf", dn: "CN=finance-r+UID=other," + base},
		{name: "duplicate CN attributes", dn: "CN=finance-r+CN=s3gateway-all-r," + base},
		{name: "CN only in ancestor", base: "CN=S3GatewayGroups,DC=example,DC=com", dn: "UID=user,CN=S3GatewayGroups,DC=example,DC=com"},
		{name: "empty CN", dn: "CN=," + base},
		{name: "blank CN", dn: `CN=\20,` + base},
		{name: "empty DN"},
		{name: "malformed DN", dn: "CN=finance-r,broken," + base},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			container := tt.base
			if container == "" {
				container = base
			}
			parsed, err := ldap.ParseDN(container)
			if err != nil {
				t.Fatal(err)
			}
			if got := trustedGroupCN(tt.dn, parsed); got != tt.want {
				t.Fatalf("trustedGroupCN(%q) = %q, want %q", tt.dn, got, tt.want)
			}
		})
	}
}

func TestTrustedGroupCNRejectsMissingContainer(t *testing.T) {
	for _, container := range []*ldap.DN{nil, {}} {
		if got := trustedGroupCN("CN=s3gateway-all-r,OU=groups", container); got != "" {
			t.Fatalf("missing container accepted group %q", got)
		}
	}
}

func TestTrustedGroupPermissions(t *testing.T) {
	const base = "OU=S3GatewayGroups,DC=example,DC=com"
	container, err := ldap.ParseDN(base)
	if err != nil {
		t.Fatal(err)
	}
	groups := make(map[string]struct{})
	for _, dn := range []string{
		"CN=finance-r," + base,
		"CN=finance-w,OU=Delegated,DC=example,DC=com",
		"CN=s3gateway-all-r,OU=Delegated,DC=example,DC=com",
		"CN=s3gateway-all-r,OU=Delegated," + base,
	} {
		if cn := trustedGroupCN(dn, container); cn != "" {
			groups[strings.ToLower(cn)] = struct{}{}
		}
	}
	rules := authz.RulesFromGroups(groups)
	if !authz.CanRead(rules, "finance-data") || authz.CanWrite(rules, "finance-data") {
		t.Fatalf("expected finance read-only permission, got %v", rules)
	}
	if authz.CanReadAll(rules) || authz.CanRead(rules, "other-data") {
		t.Fatalf("untrusted groups granted cross-namespace access: %v", rules)
	}
}
