package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"time"
)

type StartTLSLDAPResult struct {
	HasStartTLS          bool
	IsLDAPServer         bool
	HasRespondedStartTLS bool
	ResultCode           uint16
	MatchedDN            string
	DiagnosticMessage    string
	LdapError            error
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
	errorStr := ""
	if t.LdapError != nil {
		errorStr = t.LdapError.Error()
	}

	// "id", "starttls", "ldap_server", "responded_to_starttls", "result_code", "matched_dn", "diagnostic_message", "error_data",
	return writer.Write([]string{
		parentResult.Id.ToString(),
		misc.ToCompactBinary(&t.HasStartTLS),
		misc.ToCompactBinary(&t.IsLDAPServer),
		misc.ToCompactBinary(&t.HasRespondedStartTLS),
		strconv.Itoa(int(t.ResultCode)),
		t.MatchedDN,
		t.DiagnosticMessage,
		errorStr,
	})

}
