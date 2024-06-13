package results

import (
	"encoding/base64"
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
	"time"
)

type LDAPRootDSERawResult struct {
	RawResponse []byte
}

func (t *LDAPRootDSERawResult) GetCsvFileName() string {
	return FileLDAPRootDSERaw
}

func (t *LDAPRootDSERawResult) GetCsvHeader() []string {
	return []string{
		"id",
		"ip",
		"port",
		"raw_response",
	}
}

func (t *LDAPRootDSERawResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}
	// TODO i need the 		packet, err := l.readPacket(msgCtx) packet output entirely
	// or use the go lib and categorize directly
	ldapRawResponse := base64.StdEncoding.EncodeToString(t.RawResponse)
	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		ldapRawResponse,
	})

}
