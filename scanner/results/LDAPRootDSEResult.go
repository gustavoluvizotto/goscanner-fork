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

type AttributeNameValues struct {
	AttributeName   string
	AttributeValues []string
}

type LDAPRootDSEResult struct {
	LdapResult              LDAPGeneralResult
	AttributeNameValuesList []AttributeNameValues
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
		"matched_dn",
		"error_data",
		"attribute_names",
		"attribute_values_list",
	}
}

func (t *LDAPRootDSEResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}
	matchedDn := strings.Replace(t.LdapResult.MatchedDN, "\n", " ", -1)

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	attributeNames, attributeValues := LDAPAttrFormat(t.AttributeNameValuesList)

	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		matchedDn,
		errorStr,
		attributeNames,
		attributeValues,
	})

}

func LDAPAttrFormat(t []AttributeNameValues) (string, string) {
	attributeNames := "["
	attributeValues := "["
	for _, nameValues := range t {
		attributeNames += "'" + strings.Replace(nameValues.AttributeName, "'", " ", -1) + "'" + ","
		attributeValues += "["
		for _, value := range nameValues.AttributeValues {
			attributeValues += "'" + strings.Replace(value, "'", " ", -1) + "'" + ","
		}
		attributeValues += "],"
	}
	attributeNames += "]"
	attributeValues += "]"
	return attributeNames, attributeValues
}
