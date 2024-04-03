package scans

import (
	"errors"
	"github.com/gustavoluvizotto/ldap-fork/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"time"
)

type LDAPCrawlScan struct {
	keyLogFile io.Writer
}

func (s *LDAPCrawlScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *LDAPCrawlScan) GetDefaultPort() int {
	return 389
}

func (s *LDAPCrawlScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	log.Debug().Str("target", target.Ip).Msg("LDAP crawl scan started!")
	if conn == nil {
		log.Error().Str("target", target.Ip).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// TODO receive isTLS bool from the pipeline
	l := ldap.NewConn(conn, false)
	ldapResult := results.LDAPResult{}

	// rfc4513#section-5.1.1, Anonymous Bind
	err := l.UnauthenticatedBind("")
	if err != nil {
		return conn, err
	}
	defer func(l *ldap.Conn) {
		err := l.Unbind()
		if err != nil {
			log.Error().Err(err).Msg("Error unbinding")
		}
	}(l)

	filter := "(objectClass=*)"
	attributes := []string{"subschemaSubentry"}
	req := ldap.SearchRequest{
		BaseDN:       "dc=*", // TODO what is the baseDN?
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.DerefAlways,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       filter,
		Attributes:   attributes,
		Controls:     []ldap.Control{},
	}
	ent, err := l.Search(&req)
	for i := range ent.Entries {
		ent.Entries[i].PrettyPrint(4)
	}

	addLDAPResult(result, synStart, synEnd, err, &ldapResult)

	return conn, nil
}
