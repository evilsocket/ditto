package main

import (
	"fmt"
	"github.com/domainr/whois"
	"github.com/evilsocket/islazy/async"
	"github.com/jpillora/go-tld"
	whoisparser "github.com/likexian/whois-parser-go"
	"golang.org/x/net/idna"
	"net"
	"time"
)

func genEntriesForString(s string) []string{
	permutations := []string{}

	for i, c := range s {
		if substitutes, found := dictionary[c]; found {
			for _, sub := range substitutes {
				permutations = append(permutations, s[:i] + sub + s[i+1:])
				if limit > 0 && len(permutations) == limit {
					return permutations
				}
			}
		}
	}

	return permutations
}

func generateTLDPermutations(parsed *tld.URL) {
	entries = make([]*Entry, 0)
	for _, tld := range TLDs {
		if tld != parsed.TLD {
			entries = append(entries, &Entry{
				Domain: fmt.Sprintf("%s.%s", parsed.Domain, tld),
			})
			if limit > 0 && len(entries) == limit {
				return
			}
		}
	}
}

func generateHomographPermutations(parsed *tld.URL) {
	entries = make([]*Entry, 0)
	for i, c := range parsed.Domain {
		if substitutes, found := dictionary[c]; found {
			for _, sub := range substitutes {
				entries = append(entries, &Entry{
					Domain: fmt.Sprintf("%s%s%s.%s", parsed.Domain[:i], sub, parsed.Domain[i+1:], parsed.TLD),
				})
				if limit > 0 && len(entries) == limit {
					return
				}
			}
		}
	}
}

func isAvailable(domain string) (bool, *whoisparser.WhoisInfo) {
	req, err := whois.NewRequest(domain)
	if err != nil {
		return true, nil
	}

	resp, err := whois.DefaultClient.Fetch(req)
	if err != nil {
		return true, nil
	}

	parsed, err := whoisparser.Parse(string(resp.Body))
	if err != nil {
		return true, nil
	}

	if parsed.Domain == nil || parsed.Domain.CreatedDate == "" {
		return true, nil
	}

	return false, &parsed
}

func processEntry(arg async.Job) {
	defer progress.Increment()

	// don't kill WHOIS servers and DNS resolvers
	time.Sleep(time.Duration(throttle) * time.Millisecond)

	entry := arg.(*Entry)
	entry.Available, entry.Whois = isAvailable(entry.Domain)
	entry.Ascii, _ = idna.ToASCII(entry.Domain)
	// some whois might only be accepting ascii encoded domain names
	if entry.Available {
		entry.Available, entry.Whois = isAvailable(entry.Ascii)
	}

	if !entry.Available {
		entry.Addresses, _ = net.LookupHost(entry.Ascii)
		uniq := make(map[string]bool)
		for _, addr := range entry.Addresses {
			names, _ := net.LookupAddr(addr)
			for _, name := range names {
				uniq[name] = true
			}
		}
		for name, _ := range uniq {
			entry.Names = append(entry.Names, name)
		}
	}
}
