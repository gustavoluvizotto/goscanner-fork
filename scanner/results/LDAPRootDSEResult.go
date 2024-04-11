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

type LDAPAttribute struct {
	Name   string
	Values []string
}

type LDAPSearchEntry struct {
	DN         string
	Attributes []LDAPAttribute
}

type LDAPRootDSEResult struct {
	LdapResult        LDAPGeneralResult
	LdapSearchEntries []LDAPSearchEntry
}

func (t *LDAPRootDSEResult) GetCsvFileName() string {
	return FileLDAPRootDSE
}

func (t *LDAPRootDSEResult) GetCsvHeader() []string {
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

func (t *LDAPRootDSEResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	matchedDns, attributeNames, attributeValues := LDAPAttrFormat(t.LdapSearchEntries)

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

func LDAPAttrFormat(entries []LDAPSearchEntry) (string, string, string) {
	Dns := "["
	attributeNames := "["
	attributeValues := "["

	for _, nameValues := range entries {
		convDn := strings.ToValidUTF8(strings.Replace(nameValues.DN, "'", " ", -1), " ")
		Dns += "'" + convDn + "'" + ","
		attributeNames += "["
		attributeValues += "["
		for _, attr := range nameValues.Attributes {
			convAttrName := strings.ToValidUTF8(strings.Replace(attr.Name, "'", " ", -1), " ")
			attributeNames += "'" + convAttrName + "'" + ","
			attributeValues += "["
			for _, value := range attr.Values {
				convAttrVal := strings.ToValidUTF8(strings.Replace(value, "'", " ", -1), " ")
				attributeValues += "'" + convAttrVal + "'" + ","
			}
			attributeValues += "],"
		}
		attributeNames += "],"
		attributeValues += "],"
	}

	Dns += "]"
	attributeNames += "]"
	attributeValues += "]"
	return Dns, attributeNames, attributeValues
}
