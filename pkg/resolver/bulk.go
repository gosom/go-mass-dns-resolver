package resolver

import (
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type receivedJob struct {
	B []byte
	N int
}

type DnsRequest struct {
	ID    uint16
	Name  string
	Err   error
	Ips   []net.IP
	Retry int
}

type BulkResolver struct {
	conn            net.Conn
	iq              <-chan DnsRequest
	pending         map[string]int
	possibleTimeout chan DnsRequest
	lock            *sync.Mutex
	closed          bool
}

func New(iq <-chan DnsRequest, server string) (*BulkResolver, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	ans := BulkResolver{
		conn:            conn,
		iq:              iq,
		pending:         make(map[string]int),
		possibleTimeout: make(chan DnsRequest, 10000),
		lock:            &sync.Mutex{},
	}
	return &ans, nil
}

func (o *BulkResolver) process(req DnsRequest) error {
	questions, err := newQuestions(req.Name)
	if err != nil {
		return err
	}
	_, b, err := newRequest(questions)
	if err != nil {
		return err
	}
	o.lock.Lock()
	o.pending[req.Name] = 1
	o.lock.Unlock()
	if _, err := o.conn.Write(b); err != nil {
		return err
	}
	req.Retry++
	o.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if req.Retry < 10 {
		time.AfterFunc(2*time.Second, func() {
			o.lock.Lock()
			defer o.lock.Unlock()
			if !o.closed {
				if _, ok := o.pending[req.Name]; ok {
					o.possibleTimeout <- req
					o.pending[req.Name]++
				}
			}
		})
	} else {
		log.Println(req)
	}
	return nil
}

func (o *BulkResolver) send() (<-chan struct{}, <-chan error) {
	sendingDelay := time.Duration(1000000000/1000) * time.Nanosecond
	outc := make(chan struct{}, 1024)
	errc := make(chan error, 1)
	go func() {
		defer close(outc)
		defer close(errc)
		lastRound := false
		exit1 := false
		exit2 := false
		for {
			select {
			case req, ok := <-o.iq:
				if !ok {
					if !lastRound {
						lastRound = true
						time.Sleep(4 * time.Second) // TODO find a smart way
					} else if !exit1 {
						exit1 = true
					}
					break
				}
				if err := o.process(req); err != nil {
					errc <- err
					return
				}
				outc <- struct{}{}
				time.Sleep(sendingDelay)
			case req, ok := <-o.possibleTimeout:
				if !ok {
					exit2 = true
					break
				}
				if err := o.process(req); err != nil {
					errc <- err
					return
				}
				outc <- struct{}{}
				time.Sleep(time.Duration(req.Retry) * sendingDelay * 2)
			}
			if exit1 && exit2 {
				return
			}
			if exit1 && lastRound && !o.closed {
				close(o.possibleTimeout)
				o.lock.Lock()
				o.closed = true
				o.lock.Unlock()
			}
		}
	}()
	return outc, errc
}

func (o *BulkResolver) parser(received <-chan receivedJob) (<-chan DnsRequest, <-chan error) {
	outc := make(chan DnsRequest, 5000)
	errc := make(chan error, 1)
	go func() {
		defer close(outc)
		defer close(errc)
		for j := range received {
			b := j.B
			n := j.N
			var p dnsmessage.Parser
			h, err := p.Start(b[:n])
			if err != nil {
				errc <- err
				return
			}
			q, err := p.Question()
			if err != nil {
				errc <- err
				return
			}
			o.lock.Lock()
			delete(o.pending, q.Name.String())
			o.lock.Unlock()

			if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
				errc <- err
				return
			}

			if err := checkHeader(&p, h); err != nil {
				if err == errNoSuchHost || err == errServerMisbehaving || err == errServerTemporarlyMisbehaving {
					outc <- DnsRequest{Name: q.Name.String(), Err: err}
					continue
				} else {
					errc <- err
					return
				}
			}

			if err := skipToAnswer(&p); err != nil {
				if err == errNoSuchHost {
					outc <- DnsRequest{Name: q.Name.String(), Err: err}
					continue
				}
				errc <- err
				return
			}
			ips, err := getIps(&p)
			if err != nil {
				errc <- err
				return
			}
			outc <- DnsRequest{Name: q.Name.String(), Ips: ips}
		}
	}()
	return outc, errc
}

func (o *BulkResolver) receive(sent <-chan struct{}) (<-chan receivedJob, <-chan error) {
	outc := make(chan receivedJob, 15000)
	errc := make(chan error, 1)
	go func() {
		defer close(outc)
		defer close(errc)
		for _ = range sent {
			b := make([]byte, 4096)
			n, err := o.conn.Read(b)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if err != nil {
				errc <- err
				return
			}
			job := receivedJob{N: n, B: b[:n]}
			outc <- job
		}
	}()
	return outc, errc
}

func (o *BulkResolver) Run() (<-chan DnsRequest, <-chan error) {
	var errors []<-chan error
	sendRequests, tmpErr := o.send()
	errors = append(errors, tmpErr)

	receiveRequests, tmpErr2 := o.receive(sendRequests)
	errors = append(errors, tmpErr2)

	var results []<-chan DnsRequest
	for i := 0; i < 4; i++ {
		finished, tmpErr3 := o.parser(receiveRequests)
		results = append(results, finished)
		errors = append(errors, tmpErr3)
	}

	return CombineResults(results...), combineErrors(errors...)
}
