package resolver

import (
	"errors"
	//"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	errNoSuchHost                = errors.New("no such host")
	errLameReferral              = errors.New("lame referral")
	errCannotUnmarshalDNSMessage = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage   = errors.New("cannot marshal DNS message")
	errServerMisbehaving         = errors.New("server misbehaving")
	errInvalidDNSResponse        = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer     = errors.New("no answer from DNS server")

	// errServerTemporarlyMisbehaving is like errServerMisbehaving, except
	// that when it gets translated to a DNSError, the IsTemporary field
	// gets set to true.
	errServerTemporarlyMisbehaving = errors.New("server misbehaving")
)

func newQuestions(host string) ([]dnsmessage.Question, error) {
	// TODO only A records for now
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, err
	}
	q := dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	return []dnsmessage.Question{q}, err
}

func newRequest(questions []dnsmessage.Question) (id uint16, udpReq []byte, err error) {
	id = uint16(rand.Int()) ^ uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Questions: questions,
	}
	msg.ID = id
	msg.RecursionDesired = true
	pack, err := msg.Pack()
	// TODO does it fit to max UDP size? Consider using the dnsmessage.Builder with compression
	return msg.ID, pack, err
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}

	// TODO check name equality as here: https://golang.org/src/net/dnsclient_unix.go
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class {
		return false
	}
	if respHdr.Truncated {
		return false
	}
	return true
}
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}

	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarlyMisbehaving
		}
		return errServerMisbehaving
	}

	return nil
}
func skipToAnswer(p *dnsmessage.Parser) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == dnsmessage.TypeA {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func getIps(p *dnsmessage.Parser) ([]net.IP, error) {
	var gotIPs []net.IP
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return gotIPs, err
		}

		// TODO only A records for now
		if (h.Type != dnsmessage.TypeA) || h.Class != dnsmessage.ClassINET {
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.A[:])
		}
	}
	return gotIPs, nil
}

func resolv(conn net.Conn, host string) ([]net.IP, error) {
	questions, err := newQuestions(host)
	if err != nil {
		return nil, err
	}
	id, b, err := newRequest(questions)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	// TODO size here ?
	b = make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	n, err := conn.Read(b)
	if err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	if !checkResponse(id, questions[0], h, q) {
		return nil, errors.New("DNS ERROR REPLACE")
	}
	if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
		return nil, errors.New("cannot skip question")
	}

	if err := checkHeader(&p, h); err != nil {
		return nil, err
	}

	if err := skipToAnswer(&p); err != nil {
		return nil, err
	}
	return getIps(&p)
}

func LookupHost(host string, server string) ([]net.IP, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return resolv(conn, host)
}

func CombineResults(cs ...<-chan DnsRequest) <-chan DnsRequest {
	var wg sync.WaitGroup
	out := make(chan DnsRequest, len(cs))
	output := func(c <-chan DnsRequest) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out

}

func WaitErrors(errs ...<-chan error) error {
	for err := range combineErrors(errs...) {
		if err != nil {
			return err
		}
	}
	return nil
}

func combineErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	out := make(chan error, len(cs))
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
