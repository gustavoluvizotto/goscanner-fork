package results

import (
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
	"strconv"
	"strings"
	"time"
)

type LDAPSchemaResult struct {
	LdapResult              LDAPGeneralResult
	AttributeNameValuesList []AttributeNameValues
}

func (t *LDAPSchemaResult) GetCsvFileName() string {
	return FileLDAPSchema
}

func (t *LDAPSchemaResult) GetCsvHeader() []string {
	return []string{
		"id",
		"ip",
		"port",
		"result_code",
		"matched_dn",
		"error_data",
		"attribute_names",
		"attribute_values_list",
	}
}

func (t *LDAPSchemaResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}
	matchedDn := strings.Replace(t.LdapResult.MatchedDN, "\n", " ", -1)
	diagnosticMessage := strings.Replace(t.LdapResult.DiagnosticMessage, "\n", " ", -1)

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	attributeNames, attributeValues := LDAPAttrFormat(t.AttributeNameValuesList)

	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		misc.ToCompactBinary(&t.LdapResult.IsLDAPServer),
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		matchedDn,
		diagnosticMessage,
		errorStr,
		attributeNames,
		attributeValues,
	})

}
