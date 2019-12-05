package main

import (
	"bufio"
	"fmt"
	"github.com/gosom/go-mass-dns-resolver/pkg/resolver"
	"io"
	"log"
	"os"
)

func readDomains(r io.Reader) (<-chan resolver.DnsRequest, <-chan error) {
	outc := make(chan resolver.DnsRequest)
	errc := make(chan error, 1)
	go func() {
		defer close(outc)
		defer close(errc)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			outc <- resolver.DnsRequest{Name: scanner.Text() + "."}
		}

		if err := scanner.Err(); err != nil {
			errc <- err
		}
	}()
	return outc, errc
}

func main() {
	var errorChannels []<-chan error
	domains, errc := readDomains(os.Stdin)
	errorChannels = append(errorChannels, errc)

	servers := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "8.8.4.4:53", "64.6.64.6:53"}
	//servers := []string{"8.8.8.8:53"} //, "8.8.4.4:53"}
	var resultChannels []<-chan resolver.DnsRequest
	for i := range servers {
		resolv, err := resolver.New(domains, servers[i])
		if err != nil {
			log.Fatal(err)
		}
		results, resolvError := resolv.Run()
		resultChannels = append(resultChannels, results)
		errorChannels = append(errorChannels, resolvError)
	}

	for res := range resolver.CombineResults(resultChannels...) {
		fmt.Println(res)
	}

	if err := resolver.WaitErrors(errorChannels...); err != nil {
		log.Fatal(err)
	}

}
