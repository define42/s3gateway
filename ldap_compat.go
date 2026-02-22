package main

import (
	"time"

	"github.com/define42/s3gateway/internal/auth"
	ldap "github.com/go-ldap/ldap/v3"
)

func ldapDialWithTimeout(ldapURL string, timeout time.Duration) (*ldap.Conn, error) {
	return auth.LdapDialWithTimeout(ldapURL, timeout)
}

func fetchGroupsUPN(cfg Config, upn, password string) (map[string]struct{}, error) {
	return auth.FetchGroupsUPN(cfg.LDAPURL, cfg.LDAPDomain, cfg.BaseDN, upn, password)
}
