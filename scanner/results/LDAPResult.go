package results

import (
	"encoding/csv"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
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
	errorStr := ""
	if t.LdapResult.LdapError != nil {
		errorStr = t.LdapResult.LdapError.Error()
	}

	unbindResponse := ""
	if t.UnbindResponse != nil {
		unbindResponse = t.UnbindResponse.Data.String()
	}

	unbindErrorStr := ""
	if t.UnbindError != nil {
		unbindErrorStr = t.UnbindError.Error()
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		misc.ToCompactBinary(&t.LdapResult.IsLDAPServer),
		strconv.Itoa(int(t.LdapResult.ResultCode)),
		t.LdapResult.MatchedDN,
		t.LdapResult.DiagnosticMessage,
		errorStr,
		misc.ToCompactBinary(&t.HasRespondedNoticeOfDisconnection),
		unbindResponse,
		unbindErrorStr,
	})

}
