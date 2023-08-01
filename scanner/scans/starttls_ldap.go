package scans

import (
	"errors"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"
)

type StartTLSLDAP struct {
	messageID  uint32
	keyLogFile io.Writer
}

func (s *StartTLSLDAP) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *StartTLSLDAP) GetDefaultPort() int {
	return 389
}

func (s *StartTLSLDAP) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration,
	synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (rconn net.Conn, err error) {

	defer func() {
		if err != nil && conn != nil {
			// starttls connection must be finished so the next scans may succeed
			rconn, _, _, err = reconnect(conn, timeout)
			if err != nil {
				rconn = nil // could not reconnect, then stopping
			}
		}
	}()

	if conn == nil {
		log.Error().Str("ServerName", target.Domain).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.nextMessageID(), "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, ldapStartTLSOID, "TLS Extended Command"))
	packet.AppendChild(request)
	log.Debug().Str("requestPacket", packet.Data.String()).Msg("Send request")

	n, err := conn.Write(packet.Bytes())
	sTlsLdapResult := results.StartTLSLDAPResult{HasStartTLS: false}
	if err != nil {
		log.Debug().Str("n", strconv.FormatInt(int64(n), 10)).Msg("write n bytes")
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return conn, err
	}

	packetResponse := make([]byte, 1024) // typical right response is the ldapStartTLSOID, rfc4511#section-4.14.2
	n, err = conn.Read(packetResponse)
	if err != nil {
		log.Debug().Str("n", strconv.FormatInt(int64(n), 10)).Msg("read n bytes")
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return conn, err
	}

	packet = ber.DecodePacket(packetResponse)
	if packet != nil {
		log.Debug().Str("responsePacket", packet.Data.String()).Msg("Got response")
	}

	err = ldap.GetLDAPError(packet)
	if err != nil {
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return conn, err
	}

	err = hasLDAPStartTLSOID(packet)
	if err != nil {
		log.Debug().Str("IP", target.Ip).Msg(err.Error())
	}

	sTlsLdapResult.HasStartTLS = true
	addResult(result, synStart, synEnd, err, &sTlsLdapResult)
	return conn, nil
}

func hasLDAPStartTLSOID(packet *ber.Packet) error {
	if len(packet.Children) >= 2 && strings.Contains(packet.Children[1].Data.String(), ldapStartTLSOID) {
		return nil
	}
	return errors.New("the server did not responded with StartTLS") // not conforming with rfc4511#section-4.14.2
}

func (s *StartTLSLDAP) nextMessageID() uint32 {
	s.messageID++
	if s.messageID == 0 {
		// avoid overflow of messageID and return 0 (see rfc4511#section-4.1.1.1 for messageID = 0)
		s.messageID++
	}
	return s.messageID
}

func addResult(result *results.ScanResult, synStart time.Time, synEnd time.Time, err error, sTlsLdapResult *results.StartTLSLDAPResult) {
	sTlsLdapResult.LdapError = err
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   sTlsLdapResult,
	})
}
