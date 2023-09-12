package results

import (
	"encoding/csv"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"strings"
	"time"
)

type LDAPGeneralResult struct {
	IsLDAPServer      bool
	ResultCode        uint16
	MatchedDN         string
	DiagnosticMessage string
	LdapError         error
}

type LDAPResult struct {
	LdapResult                        LDAPGeneralResult
	HasRespondedNoticeOfDisconnection bool
	UnbindResponse                    *ber.Packet
	UnbindError                       error
}

func (t *LDAPResult) GetCsvFileName() string {
	return FileLDAP
}

func (t *LDAPResult) GetCsvHeader() []string {
	return []string{
		"id",
		"ldap_server",
		"result_code",
		"matched_dn",
		"diagnostic_message",
		"error_data",
		"responded_with_notice_of_disconnection",
		"unbind_response",
		"unbind_error",
	}
}

func (t *LDAPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	matchedDn := strings.Replace(t.LdapResult.MatchedDN, "\n", " ", -1)
	diagnosticMessage := strings.Replace(t.LdapResult.DiagnosticMessage, "\n", " ", -1)

	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = strings.Replace(t.LdapResult.LdapError.Error(), "\n", " ", -1)
	}

	unbindResponse := ""
	if t.UnbindResponse != nil {
		unbindResponse = strings.Replace(t.UnbindResponse.Data.String(), "\n", " ", -1)
	}

	unbindErrorStr := ""
	if t.UnbindError != nil {
		unbindErrorStr = strings.Replace(t.UnbindError.Error(), "\n", " ", -1)
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		misc.ToCompactBinary(&t.LdapResult.IsLDAPServer),
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		matchedDn,
		diagnosticMessage,
		errorStr,
		misc.ToCompactBinary(&t.HasRespondedNoticeOfDisconnection),
		unbindResponse,
		unbindErrorStr,
	})

}