package config

import (
	"strings"
	"testing"
)

func TestAdminPublicOriginValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		want string
		bad  bool
	}{
		{name: "unset"},
		{name: "blank", raw: " \t "},
		{name: "HTTPS", raw: "https://gateway.example", want: "https://gateway.example"},
		{name: "HTTP", raw: "http://localhost:8080", want: "http://localhost:8080"},
		{name: "case and default HTTPS port", raw: " HTTPS://GATEWAY.EXAMPLE:443 ", want: "https://gateway.example"},
		{name: "default HTTP port", raw: "http://gateway.example:80", want: "http://gateway.example"},
		{name: "IPv6", raw: "https://[::1]:443", want: "https://[::1]"},
		{name: "custom port", raw: "https://gateway.example:8443", want: "https://gateway.example:8443"},
		{name: "relative", raw: "gateway.example", bad: true},
		{name: "protocol relative", raw: "//gateway.example", bad: true},
		{name: "other protocol", raw: "ftp://gateway.example", bad: true},
		{name: "missing host", raw: "https://", bad: true},
		{name: "opaque URL", raw: "https:gateway.example", bad: true},
		{name: "userinfo", raw: "https://user:pass@gateway.example", bad: true},
		{name: "path", raw: "https://gateway.example/admin", bad: true},
		{name: "trailing slash", raw: "https://gateway.example/", bad: true},
		{name: "query", raw: "https://gateway.example?next=admin", bad: true},
		{name: "empty query", raw: "https://gateway.example?", bad: true},
		{name: "fragment", raw: "https://gateway.example#admin", bad: true},
		{name: "empty fragment", raw: "https://gateway.example#", bad: true},
		{name: "zero port", raw: "https://gateway.example:0", bad: true},
		{name: "large port", raw: "https://gateway.example:65536", bad: true},
		{name: "empty port", raw: "https://gateway.example:", bad: true},
		{name: "nonnumeric port", raw: "https://gateway.example:https", bad: true},
		{name: "unbracketed IPv6", raw: "https://::1", bad: true},
		{name: "invalid IPv6", raw: "https://[invalid]", bad: true},
		{name: "host whitespace", raw: "https://gateway .example", bad: true},
		{name: "multiple origins", raw: "https://gateway.example https://other.example", bad: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAdminPublicOrigin(tt.raw)
			if (err != nil) != tt.bad || (!tt.bad && got != tt.want) {
				t.Fatalf("normalized origin = %q, error = %v; want %q, invalid = %t", got, err, tt.want, tt.bad)
			}
			cfg := Config{
				S3GatewayPrivateX25519Key: mustTestX25519PrivateKey(t),
				UpstreamEndpoint:          "https://s3.example",
				LDAPGroupBaseDN:           "ou=groups,dc=example,dc=com",
				AdminPublicOrigin:         tt.raw,
			}
			cfg.ApplyDefaults()
			err = cfg.Validate()
			if (err != nil) != tt.bad || (err != nil && !strings.Contains(err.Error(), "ADMIN_PUBLIC_ORIGIN")) {
				t.Fatalf("config validation error = %v; want invalid origin = %t", err, tt.bad)
			}
		})
	}
}

func TestLoadConfigAdminPublicOrigin(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")
	for _, value := range []string{"", "https://gateway.example"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ADMIN_PUBLIC_ORIGIN", value)
			if got := LoadConfig().AdminPublicOrigin; got != value {
				t.Fatalf("loaded origin = %q, want %q", got, value)
			}
		})
	}
}
