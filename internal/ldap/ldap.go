// Package ldap authenticates users and retrieves Active Directory group
// membership over LDAP.
package ldap

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/define42/s3gateway/internal/authn"
	"github.com/define42/s3gateway/internal/config"
	ldap "github.com/go-ldap/ldap/v3"
)

const defaultLDAPOperationTimeout = 10 * time.Second

// ==================== AD group lookup ====================
func ldapDial(ldapURL string, timeout time.Duration) (*ldap.Conn, error) {
	return DialWithTimeout(ldapURL, timeout)
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
// lowercase common names from memberOf only for groups directly inside
// cfg.LDAPGroupBaseDN. It fails unless the container is valid and the search
// yields exactly one user entry.
func FetchGroupsUPN(cfg config.Config, upn, password string) (map[string]struct{}, error) {
	groupContainer, err := cfg.LDAPGroupContainerDN()
	if err != nil {
		return nil, err
	}
	operationTimeout := cfg.LDAPOperationTimeout
	if operationTimeout <= 0 {
		operationTimeout = defaultLDAPOperationTimeout
	}
	conn, err := ldapDial(cfg.LDAPURL, operationTimeout)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(operationTimeout)

	upnWithDomain := upn + "@" + ldap.EscapeFilter(cfg.LDAPDomain)

	if err := conn.Bind(upnWithDomain, password); err != nil {
		return nil, wrapBindError(err)
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
		if cn := trustedGroupCN(dn, groupContainer); cn != "" {
			groups[strings.ToLower(cn)] = struct{}{}
		}
	}
	return groups, nil
}

func wrapBindError(err error) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return fmt.Errorf("ldap bind failed: %w: %w", authn.ErrRejectedCredentials, err)
	}
	return fmt.Errorf("ldap bind failed: %w", err)
}

func trustedGroupCN(dn string, container *ldap.DN) string {
	if container == nil || len(container.RDNs) == 0 {
		return ""
	}
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil || len(parsed.RDNs) != len(container.RDNs)+1 {
		return ""
	}
	// Compare the parsed immediate parent, not a string suffix or any ancestor:
	// groups in delegated child containers must not inherit gateway authority.
	parent := &ldap.DN{RDNs: parsed.RDNs[1:]}
	if !parent.EqualFold(container) {
		return ""
	}
	leaf := parsed.RDNs[0]
	if len(leaf.Attributes) != 1 || !strings.EqualFold(leaf.Attributes[0].Type, "CN") {
		return ""
	}
	return strings.TrimSpace(leaf.Attributes[0].Value)
}
