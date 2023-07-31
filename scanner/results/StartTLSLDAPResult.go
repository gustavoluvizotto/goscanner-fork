package results

import (
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"time"
)

type StartTLSLDAPResult struct {
	HasStartTLS bool
	LdapError   error
}

func (t *StartTLSLDAPResult) GetCsvFileName() string {
	return FileStartTLSLDAP
}

func (t *StartTLSLDAPResult) GetCsvHeader() []string {
	return []string{
		"id",
		"starttls",
		"error_data",
	}
}

func (t *StartTLSLDAPResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	errorStr := ""
	if t.LdapError != nil {
		errorStr = t.LdapError.Error()
	}

	return writer.Write([]string{
		parentResult.Id.ToString(),
		misc.ToCompactBinary(&t.HasStartTLS),
		errorStr,
	})

}
