package scans

import (
	"errors"
	"github.com/gustavoluvizotto/ldap-fork/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"time"
)

type LDAPCrawlScan struct {
	keyLogFile io.Writer
}

func (s *LDAPCrawlScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *LDAPCrawlScan) GetDefaultPort() int {
	return 389
}

func (s *LDAPCrawlScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	log.Debug().Str("target", target.Ip).Msg("LDAP crawl scan started!")
	if conn == nil {
		log.Error().Str("target", target.Ip).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}
	defer conn.Close()

	isTls := false
	for _, r := range result.SubResults {
		if r.Result.GetCsvFileName() == results.FileStartTLSLDAP {
			isTls = true
			break
		}
	}
	ldapConn := ldap.NewConn(conn, isTls)
	ldapConn.Start()

	// rfc4513#section-5.1.1, Anonymous Bind
	err := ldapConn.UnauthenticatedBind("")
	if err != nil {
		return conn, err
	}
	defer ldapConn.Unbind()

	// search schema (rfc4512#section-4.4)
	filter := "(objectClass=subschema)"
	scope := ldap.ScopeBaseObject
	baseDN := "cn=subschema"
	attributes := []string{"*", "+"}
	limit := 0
	schemaEntries, err := SearchAndGetEntries(ldapConn, baseDN, scope, filter, attributes, limit)

	ldapSchemaResult := results.LDAPSchemaResult{}
	var ldapError *ldap.Error
	errors.As(err, &ldapError)
	if ldapError != nil {
		ldapSchemaResult.LdapResult.ResultCode = ldapError.ResultCode
	}
	ldapSchemaResult.LdapResult.LdapError = err
	ldapSchemaResult.AttributeNameValuesList = schemaEntries
	ldapSchemaResult.LdapResult.MatchedDN = baseDN
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   &ldapSchemaResult,
	})

	// rfc4512#section-5.1 root dse search
	// https://ldap.com/dit-and-the-ldap-root-dse/
	// https://nmap.org/nsedoc/scripts/ldap-rootdse.html
	// https://learn.microsoft.com/en-us/windows/win32/adschema/rootdse
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db
	// https://www.ibm.com/docs/en/svd/10.0.2?topic=dse-attributes-in-root
	filter = "(objectClass=*)"
	baseDN = ""
	scope = ldap.ScopeBaseObject
	// "It is noted that root DSE attributes are operational and, like other operational attributes,
	// are not returned in search requests unless requested by name."
	attributes = []string{
		"altServer",
		"namingContexts",
		"supportedControl",
		"supportedExtension",
		"supportedFeatures",
		"supportedLDAPVersion",
		"supportedSASLMechanisms",
		"supportedAuthPasswordSchemes",
		"vendorName",
		"vendorVersion",
		"supportedLDAPPolicies",
		"supportedCapabilities",
		"ldapServiceName",
		"isGlobalCatalogReady",
		"dnsHostName",
		"serverName",
		"dsaVersionString",
		"subschemaSubentry",
		"ibmdirectoryversion",
		"ibm-enabledcapabilities",
		"ibm-supportedcapabilities",
		"ibm-sasldigestrealmname",
		"ibm-ldapservicename",
		"ibm-tlsciphers",
		"ibm-slapdTlsExtSigScheme",
		"ibm-slapdTlsExtSigSchemeCert",
		"ibm-slapdTlsExtSupportedGroups",
		"o", "ou"} // additional attributes - trying to get more information
	limit = 0
	rootDseEntries, err := SearchAndGetEntries(ldapConn, baseDN, scope, filter, attributes, limit)

	ldapRootDSEResult := results.LDAPRootDSEResult{}
	errors.As(err, &ldapError)
	if ldapError != nil {
		ldapSchemaResult.LdapResult.ResultCode = ldapError.ResultCode
	}
	ldapRootDSEResult.LdapResult.LdapError = err
	ldapRootDSEResult.LdapSearchEntries = rootDseEntries
	ldapRootDSEResult.LdapResult.MatchedDN = baseDN
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   &ldapRootDSEResult,
	})
	return conn, nil
}

func SearchAndGetEntries(ldapConn *ldap.Conn, baseDN string, scope int, filter string, attributes []string, limit int) ([]results.LDAPSearchEntry, error) {
	req := ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        scope,
		DerefAliases: ldap.DerefAlways,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       filter,
		Attributes:   attributes,
		Controls:     nil,
	}
	searchResult, err := ldapConn.Search(&req)
	resultEntries := make([]results.LDAPSearchEntry, 0)
	if searchResult != nil {
		resultEntries = make([]results.LDAPSearchEntry, len(searchResult.Entries))
		for i, ent := range searchResult.Entries {
			resultEntries[i].DN = ent.DN
			resultEntries[i].Attributes = make([]results.LDAPAttribute, len(ent.Attributes))
			for j, attr := range ent.Attributes {
				resultEntries[i].Attributes[j] = results.LDAPAttribute{
					Name:   attr.Name,
					Values: attr.Values,
				}
			}
			if limit != 0 && i == limit {
				break
			}
		}
	}
	return resultEntries, err
}
