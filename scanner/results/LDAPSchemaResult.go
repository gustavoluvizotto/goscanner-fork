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
	AttributeNameValuesList []LDAPSearchEntry
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
		"error_data",
		"matched_dns",
		"attribute_names",
		"attribute_values_list",
	}
}

func (t *LDAPSchemaResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	matchedDns, attributeNames, attributeValues := LDAPAttrFormat(t.AttributeNameValuesList)

	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		errorStr,
		matchedDns,
		attributeNames,
		attributeValues,
	})

}
