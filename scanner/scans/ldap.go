package scans

import (
	"encoding/hex"
	"errors"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"time"
)

const noticeOfDisconnectionOID = "1.3.6.1.4.1.1466.20036"

type LDAPScan struct {
	keyLogFile io.Writer
}

func (s *LDAPScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *LDAPScan) GetDefaultPort() int {
	return 389
}

func (s *LDAPScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	log.Debug().Str("target", target.Ip).Msg("LDAP scan started!")
	if conn == nil {
		log.Error().Str("target", target.Ip).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	unusualVersion := 4
	username := ""
	password := ""
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, nextMessageID(), "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, unusualVersion, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "User Name"))
	// simple authentication, AuthenticationChoice := [0] OCTET STRING
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "Password"))
	packet.AppendChild(request)
	log.Debug().Str("hex", hex.EncodeToString(packet.Data.Bytes())).Str("requestPacket", packet.Data.String()).Msg("Sent request")

	ldapResult := results.LDAPResult{}
	response, conn, err := writeRequestReadDecodeResponse(conn, packet)
	if err != nil {
		addLDAPResult(result, synStart, synEnd, err, &ldapResult)
		return conn, err
	}

	ldapResult.LdapResult, err = parseLDAPResponse(response)

	oidErr := respondedWithOID(response, noticeOfDisconnectionOID)
	if oidErr == nil {
		ldapResult.HasRespondedNoticeOfDisconnection = true
	} else {
		/* rfc4511#section-4.4.2
		"If the client receives a BindResponse where the resultCode is set to
		 protocolError, it is to assume that the server does not support this
		 version of LDAP."
		"... Clients that are unable or unwilling to proceed SHOULD
		 terminate the LDAP session"
		*/
		ldapResult.UnbindResponse, ldapResult.UnbindError = unbind(conn)
	}
	// and the TCP connection is closed afterward as it should be

	addLDAPResult(result, synStart, synEnd, err, &ldapResult)

	return conn, nil
}

func addLDAPResult(result *results.ScanResult, synStart time.Time, synEnd time.Time, err error, ldapResult *results.LDAPResult) {
	ldapResult.LdapResult.LdapError = err
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   ldapResult,
	})
}

func unbind(conn net.Conn) (*ber.Packet, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, nextMessageID(), "MessageID"))
	packet.AppendChild(ber.Encode(ber.ClassApplication, ber.TypePrimitive, ldap.ApplicationUnbindRequest, nil, ldap.ApplicationMap[ldap.ApplicationUnbindRequest]))

	response, conn, err := writeRequestReadDecodeResponse(conn, packet)

	return response, err
}
