package config

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeAdminPublicOrigin validates an optional HTTP(S) origin and returns
// its lowercase form without a default port. Paths, credentials, queries, and
// fragments are not part of an origin and are rejected.
func NormalizeAdminPublicOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	invalid := errors.New("ADMIN_PUBLIC_ORIGIN must be an absolute HTTP(S) origin with a valid host and no credentials, path, query, or fragment")
	origin, err := url.Parse(raw)
	if err != nil {
		return "", invalid
	}
	origin.Scheme = strings.ToLower(origin.Scheme)
	if origin.Opaque != "" || origin.User != nil || origin.Hostname() == "" ||
		(origin.Scheme != "http" && origin.Scheme != "https") || origin.Path != "" ||
		origin.RawQuery != "" || origin.ForceQuery || strings.Contains(raw, "#") {
		return "", invalid
	}
	if strings.Contains(origin.Hostname(), ":") || strings.HasPrefix(origin.Host, "[") {
		if _, err := netip.ParseAddr(origin.Hostname()); err != nil || !strings.HasPrefix(origin.Host, "[") {
			return "", invalid
		}
	}
	port := origin.Port()
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", invalid
		}
	} else if strings.HasSuffix(origin.Host, ":") {
		return "", invalid
	}
	host := strings.ToLower(origin.Host)
	if (origin.Scheme == "https" && port == "443") || (origin.Scheme == "http" && port == "80") {
		host = strings.TrimSuffix(host, ":"+port)
	}
	return origin.Scheme + "://" + host, nil
}
