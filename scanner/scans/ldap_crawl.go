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
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

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
	defer func(l *ldap.Conn) {
		err := l.Unbind()
		if err != nil {
			log.Error().Err(err).Msg("Error unbinding")
		}
	}(ldapConn)

	// search schema (rfc4512#section-4.4)
	filter := "(objectClass=subschema)"
	scope := ldap.ScopeBaseObject
	baseDN := "cn=subschema"
	attributes := []string{"*", "+"}
	limit := 0
	attrNameVals, err := SearchAndGetEntries(ldapConn, baseDN, scope, filter, attributes, limit)

	ldapSchemaResult := results.LDAPSchemaResult{}
	var ldapError *ldap.Error
	errors.As(err, &ldapError)
	if ldapError != nil {
		ldapSchemaResult.LdapResult.ResultCode = ldapError.ResultCode
	}
	ldapSchemaResult.LdapResult.LdapError = err
	ldapSchemaResult.AttributeNameValuesList = attrNameVals
	ldapSchemaResult.LdapResult.MatchedDN = baseDN
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   &ldapSchemaResult,
	})

	// other search
	/*
		// MS AD attributes from ldap_ms_ad.json (extracted from MS website)
		// ldap_oid_dict.json: https://ldap.com/ldap-oid-reference-guide/
	*/
	filter = "(objectClass=*)"
	baseDN = "dc=utwente,dc=nl" // TODO where to get the baseDN? fhms gets from cmd args
	scope = ldap.ScopeWholeSubtree
	attributes = []string{
		"namingContexts",
		"defaultNamingContext",
		"supportedLDAPPolicies",
		"supportedLDAPVersion",
		"supportedCapabilities",
		"supportedExtension",
		"subschemaSubentry",
		"supportedControl",
		"vendorName",
		"vendorVersion",
		"o", "ou"}
	limit = 50
	attrNameVals, err = SearchAndGetEntries(ldapConn, baseDN, scope, filter, attributes, limit)

	ldapSearchResult := results.LDAPSearchResult{}
	errors.As(err, &ldapError)
	if ldapError != nil {
		ldapSchemaResult.LdapResult.ResultCode = ldapError.ResultCode
	}
	ldapSearchResult.LdapResult.LdapError = err
	ldapSearchResult.AttributeNameValuesList = attrNameVals
	ldapSearchResult.LdapResult.MatchedDN = baseDN
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   &ldapSearchResult,
	})
	return conn, nil
}

func SearchAndGetEntries(ldapConn *ldap.Conn, baseDN string, scope int, filter string, attributes []string, limit int) ([]results.AttributeNameValues, error) {
	req := ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        scope,            //ldap.ScopeWholeSubtree ScopeBaseObject
		DerefAliases: ldap.DerefAlways, //ldap.DerefAlways NeverDerefAliases
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       filter,
		Attributes:   attributes,
		Controls:     nil,
	}
	attrNameVals := make([]results.AttributeNameValues, 0)
	searchResult, err := ldapConn.Search(&req)
	if searchResult != nil {
		for i, ent := range searchResult.Entries {
			for _, attr := range ent.Attributes {
				attrNameVals = append(attrNameVals, results.AttributeNameValues{
					AttributeName:   attr.Name,
					AttributeValues: attr.Values,
				})
			}
			//ent.PrettyPrint(4)
			if limit != 0 && i == limit {
				break
			}
		}
	}
	return attrNameVals, err
}
