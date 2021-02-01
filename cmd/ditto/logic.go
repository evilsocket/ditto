package main

import (
	"encoding/json"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/domainr/whois"
	"github.com/evilsocket/islazy/async"
	"github.com/jpillora/go-tld"
	whoisparser "github.com/likexian/whois-parser-go"
	"golang.org/x/net/idna"
	"io/ioutil"
	"net"
	"sort"
	"time"
)

func genEntriesForString(s string) []string {
	permutations := []string{}

	for i, c := range s {
		if substitutes, found := dictionary[c]; found {
			for _, sub := range substitutes {
				permutations = append(permutations, s[:i]+sub+s[i+1:])
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
	for _, otherTLD := range TLDs {
		if otherTLD != parsed.TLD {
			entries = append(entries, &Entry{
				Domain: fmt.Sprintf("%s.%s", parsed.Domain, otherTLD),
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
	if !silent && !noProgressBar {
		defer progress.Increment()
	}

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

	sort.Strings(entry.Addresses)
	sort.Strings(entry.Names)
}

func updateEntries(parsed *tld.URL) {
	// deep copy entries
	if data, err := json.Marshal(entries); err != nil {
		die("error encoding entries: %v\n", err)
	} else if err = json.Unmarshal(data, &prevEntries); err != nil {
		die("error encoding prev entries: %v\n", err)
	}

	if testDataFile != "" {
		// load entries from file
		if raw, err := ioutil.ReadFile(testDataFile); err != nil {
			die("error reading %s: %v\n", testDataFile, err)
		} else if err = json.Unmarshal(raw, &entries); err != nil {
			die("error decoding %s: %v\n", testDataFile, err)
		}
	} else {
		if mutateTLD {
			// generate entries by replacing tld
			generateTLDPermutations(parsed)
		} else {
			// generate entries by homograph attack
			generateHomographPermutations(parsed)
		}

		queue = async.NewQueue(numWorkers, processEntry)

		if !silent {
			fmt.Printf("checking %d variations for '%s.%s', please wait ...\n\n", len(entries), parsed.Domain, parsed.TLD)

			if !noProgressBar {
				if progress != nil {
					progress.SetCurrent(0)
				}
				progress = pb.StartNew(len(entries))
			}
		}

		for _, entry := range entries {
			queue.Add(async.Job(entry))
		}

		queue.WaitDone()
	}
}
