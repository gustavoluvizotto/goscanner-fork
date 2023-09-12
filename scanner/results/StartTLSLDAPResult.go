package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"strings"
	"time"
)

type StartTLSLDAPResult struct {
	HasStartTLS          bool
	HasRespondedStartTLS bool
	LdapResult           LDAPGeneralResult
}

func (t *StartTLSLDAPResult) GetCsvFileName() string {
	return FileStartTLSLDAP
}

func (t *StartTLSLDAPResult) GetCsvHeader() []string {
	return []string{
		"id",
		"starttls",
		"ldap_server",
		"responded_to_starttls",
		"result_code",
		"matched_dn",
		"diagnostic_message",
		"error_data",
	}
}

func (t *StartTLSLDAPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	matchedDn := strings.Replace(t.LdapResult.MatchedDN, "\n", " ", -1)
	diagnosticMessage := strings.Replace(t.LdapResult.DiagnosticMessage, "\n", " ", -1)

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	// "id", "starttls", "ldap_server", "responded_to_starttls", "result_code", "matched_dn", "diagnostic_message", "error_data",
	return writer.Write([]string{
		parentResult.Id.ToString(),
		misc.ToCompactBinary(&t.HasStartTLS),
		misc.ToCompactBinary(&t.LdapResult.IsLDAPServer),
		misc.ToCompactBinary(&t.HasRespondedStartTLS),
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		matchedDn,
		diagnosticMessage,
		errorStr,
	})

}
