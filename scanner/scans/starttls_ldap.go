package scans

import (
	"encoding/hex"
	"errors"
	"fmt"
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

const ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"

var messageID uint32

type StartTLSLDAP struct {
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
	log.Debug().Str("target", target.Ip).Msg("StartTLS LDAP scan started!")

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
		log.Error().Str("target", target.Ip).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, nextMessageID(), "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, ldapStartTLSOID, "TLS Extended Command"))
	packet.AppendChild(request)
	log.Debug().Str("hex", hex.EncodeToString(packet.Data.Bytes())).Str("requestPacket", packet.Data.String()).Msg("Sent request")

	sTlsLdapResult := results.StartTLSLDAPResult{}
	response, conn, err := writeRequestReadDecodeResponse(conn, packet)
	if err != nil {
		addLDAPStartTLSResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return conn, err
	}

	sTlsLdapResult.LdapResult, err = parseLDAPResponse(response)
	if err == nil {
		sTlsLdapResult.HasStartTLS = true
	}
	oidErr := respondedWithOID(response, ldapStartTLSOID)
	if oidErr == nil {
		// rfc4511#section-4.14.1
		// "... StartTLS Extended response and, in the case of a successful response, completes TLS negotiations."
		//  rfc4511#section-4.14.2
		// "The responseName is "1.3.6.1.4.1.1466.20037" when provided (see Section 4.12).
		// The responseValue is always absent."
		sTlsLdapResult.HasRespondedStartTLS = true
	}
	addLDAPStartTLSResult(result, synStart, synEnd, err, &sTlsLdapResult)

	//if !sTlsLdapResult.HasRespondedStartTLS {
	//	// if result code OK, then move on with TLS handshake, otherwise reconnect
	//	err = errors.New("no StartTLS response received")
	//}
	return conn, nil
}

func nextMessageID() uint32 {
	messageID++
	if messageID == 0 {
		// avoid overflow of messageID and return 0 (see rfc4511#section-4.1.1.1 for messageID = 0)
		messageID++
	}
	return messageID
}

func writeRequestReadDecodeResponse(conn net.Conn, packet *ber.Packet) (*ber.Packet, net.Conn, error) {
	n, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Debug().Str("n", strconv.FormatInt(int64(n), 10)).Msg("write n bytes")
		return nil, conn, err
	}

	packetResponse := make([]byte, 1024) // typical right response is the ldapStartTLSOID, rfc4511#section-4.14.2
	n, err = conn.Read(packetResponse)
	if err != nil {
		log.Debug().Str("n", strconv.FormatInt(int64(n), 10)).Msg("read n bytes")
		return nil, conn, err
	}

	response := ber.DecodePacket(packetResponse)
	if response != nil {
		log.Debug().Str("hex", hex.EncodeToString(packet.Data.Bytes())).Str("responsePacket", packet.Data.String()).Msg("Got response")
	}
	return response, conn, nil
}

func addLDAPStartTLSResult(result *results.ScanResult, synStart time.Time, synEnd time.Time, err error, sTlsLdapResult *results.StartTLSLDAPResult) {
	sTlsLdapResult.LdapResult.LdapError = err
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   sTlsLdapResult,
	})
}

func parseLDAPResponse(response *ber.Packet) (results.LDAPGeneralResult, error) {
	ldapResult := results.LDAPGeneralResult{}
	err := ldap.GetLDAPError(response)
	if err != nil {
		var ldapError *ldap.Error
		errors.As(err, &ldapError)
		if ldapError.ResultCode == ldap.ErrorNetwork || ldapError.ResultCode == ldap.ErrorUnexpectedResponse {
			ldapResult.IsLDAPServer = false
		} else {
			// if there is no error, this means we could parse as a LDAP response
			ldapResult.IsLDAPServer = true
		}
		ldapResult.ResultCode = ldapError.ResultCode
		ldapResult.MatchedDN = ldapError.MatchedDN
		ldapResult.DiagnosticMessage = ldapError.Err.Error()
	} else {
		ldapResult = *getLDAPGeneralResults(response)
	}
	return ldapResult, err
}

func getLDAPGeneralResults(packet *ber.Packet) *results.LDAPGeneralResult {
	response := packet.Children[1]
	ldapResult := results.LDAPGeneralResult{IsLDAPServer: true,
		ResultCode:        uint16(response.Children[0].Value.(int64)),
		MatchedDN:         response.Children[1].Value.(string),
		DiagnosticMessage: fmt.Sprintf("%s", response.Children[2].Value.(string)),
	}

	return &ldapResult
}

func respondedWithOID(packet *ber.Packet, oid string) error {
	if packet != nil && len(packet.Children) >= 2 && packet.Children[1] != nil && strings.Contains(packet.Children[1].Data.String(), oid) {
		return nil
	} else {
		err := errors.New("the server did not responded with OID " + oid)
		return err
	}
}
