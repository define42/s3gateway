package main

import (
	"os"

	"github.com/olekukonko/tablewriter"
)

type SettingsType struct {
	m map[string]SettingType
}

type SettingType struct {
	Description string
	Value       string
}

func NewSettingType(print bool) *SettingsType {
	s := &SettingsType{m: make(map[string]SettingType)}

	//s.Set(ACME_SERVER, "ACME server url", "")
	s.Set(ACME_DOMAINS, "Comma separated domains thats used with ACME", "")
	//s.Set(LISTEN_ADDR, "Server listen address, only if not using ACME", ":8080")
	s.Set(ACME_DATA_DIR, "ACME data directory", "/data/acme/")
	//s.Set(ACME_CA_DIR, "ACME CA certificates directory", "/data/acme/ca/")
	s.Set(VDI_IMAGE_DIR, "Directory for VDI images", "/data/vdiimage/")
	s.Set(LDAP_URL, "LDAP server url", "ldaps://ldap:389")
	s.Set(LDAP_BASE_DN, "LDAP base DN", "dc=glauth,dc=com")
	s.Set(LDAP_USER_FILTER, "LDAP user filter", "(mail=%s)")
	s.Set(LDAP_USER_DOMAIN, "LDAP user mail domain", "@example.com")
	s.Set(LDAP_STARTTLS, "Use StartTLS when connecting to LDAP", "false")
	s.Set(LDAP_SKIP_TLS_VERIFY, "Skip TLS verification when connecting to LDAP", "true")
	s.Set(NTLM_DOMAIN, "NTLM domain name", "vdi")
	s.Set(RDPGW_SEND_BUF, "RD Gateway socket send buffer size (bytes)", "1048576")
	s.Set(RDPGW_RECV_BUF, "RD Gateway socket receive buffer size (bytes)", "1048576")
	s.Set(RDPGW_WS_READ_BUF, "RD Gateway websocket read buffer size (bytes)", "65536")
	s.Set(RDPGW_WS_WRITE_BUF, "RD Gateway websocket write buffer size (bytes)", "65536")
	s.Set(BASE_IMAGE_URL, "URL to download base VDI image if not found locally", "https://github.com/define42/ubuntu-desktop-cloud-image/releases/download/v0.0.25/noble-desktop-cloudimg-amd64-v0.0.25.img")

	if print {
		table := tablewriter.NewWriter(os.Stdout)

		table.Header("KEY", "Description", "value")
		for key, setting := range s.m {
			if err := table.Append([]string{key, setting.Description, setting.Value}); err != nil {
				panic(err)
			}
		}
		if err := table.Render(); err != nil {
			panic(err)
		}
	}
	return s
}

func (s *SettingsType) Get(id string) string {
	return s.m[id].Value
}

func (s *SettingsType) Has(id string) bool {
	return len(s.m[id].Value) > 0
}

func (s *SettingsType) IsTrue(id string) bool {
	return s.m[id].Value == "true"
}

func (s *SettingsType) Set(id string, description string, defaultValue string) {
	if value, ok := os.LookupEnv(id); ok {
		s.m[id] = SettingType{Description: description, Value: value}
	} else {
		s.m[id] = SettingType{Description: description, Value: defaultValue}
	}
}

const (
	//ACME_SERVER          = "ACME_SERVER"
	ACME_DOMAINS = "ACME_DOMAINS"
	//LISTEN_ADDR          = "LISTEN_ADDR"
	ACME_DATA_DIR = "ACME_DATA_DIR"
	//ACME_CA_DIR          = "ACME_CA_DIR"
	LDAP_URL             = "LDAP_URL"
	LDAP_BASE_DN         = "LDAP_BASE_DN"
	LDAP_USER_FILTER     = "LDAP_USER_FILTER"
	LDAP_USER_DOMAIN     = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS        = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY = "LDAP_SKIP_TLS_VERIFY"
	VDI_IMAGE_DIR        = "VDI_IMAGE_DIR"
	NTLM_DOMAIN          = "NTLM_DOMAIN"
	RDPGW_SEND_BUF       = "RDPGW_SEND_BUF"
	RDPGW_RECV_BUF       = "RDPGW_RECV_BUF"
	RDPGW_WS_READ_BUF    = "RDPGW_WS_READ_BUF"
	RDPGW_WS_WRITE_BUF   = "RDPGW_WS_WRITE_BUF"
	BASE_IMAGE_URL       = "BASE_IMAGE_URL"
)
