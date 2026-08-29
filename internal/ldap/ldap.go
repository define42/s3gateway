// Package ldap authenticates users and retrieves Active Directory group
// membership over LDAP.
package ldap

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/define42/s3gateway/internal/config"
	ldap "github.com/go-ldap/ldap/v3"
)

const defaultLDAPDialTimeout = 5 * time.Second

// ==================== AD group lookup ====================
func ldapDial(ldapURL string) (*ldap.Conn, error) {
	return DialWithTimeout(ldapURL, defaultLDAPDialTimeout)
}

// DialWithTimeout opens an LDAP connection using the URL's scheme and a dialer
// bounded by timeout.
func DialWithTimeout(ldapURL string, timeout time.Duration) (*ldap.Conn, error) {
	_, err := url.Parse(ldapURL)
	if err != nil {
		return nil, err
	}
	return ldap.DialURL(ldapURL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
}

// FetchGroupsUPN appends cfg.LDAPDomain to upn, binds with the resulting user
// principal name, and searches cfg.BaseDN for that identity. It returns
// lowercase common names from memberOf and fails unless the search yields
// exactly one user entry.
func FetchGroupsUPN(cfg config.Config, upn, password string) (map[string]struct{}, error) {
	conn, err := ldapDial(cfg.LDAPURL)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	upnWithDomain := upn + "@" + ldap.EscapeFilter(cfg.LDAPDomain)

	if err := conn.Bind(upnWithDomain, password); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(upnWithDomain))
	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 5, false,
		filter,
		[]string{"memberOf"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("expected 1 entry for %q, got %d", upn, len(res.Entries))
	}

	groups := make(map[string]struct{})
	for _, dn := range res.Entries[0].GetAttributeValues("memberOf") {
		if cn := cnFromDN(dn); cn != "" {
			groups[strings.ToLower(cn)] = struct{}{}
		}
	}
	return groups, nil
}

func cnFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil {
		return ""
	}
	for _, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "CN") {
				return strings.TrimSpace(a.Value)
			}
		}
	}
	return ""
}
