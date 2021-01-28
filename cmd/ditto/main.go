package main

import (
	"flag"
	"fmt"
	"github.com/evilsocket/islazy/async"
	"github.com/evilsocket/islazy/tui"
	"github.com/haccer/available"
	tld "github.com/jpillora/go-tld"
	"golang.org/x/net/idna"
	"net"
	"os"
	"strings"
)

var (
	url       = "https://www.ice.gov"
	limit     = 0
	entries   = make([]*Entry, 0)
	queue     = async.NewQueue(0, processEntry)
	availOnly = false
	regOnly   = false
)

func die(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func init() {
	flag.StringVar(&url, "domain", url, "Domain name or url.")
	flag.IntVar(&limit, "limit", limit, "Limit the number of permutations.")
	flag.BoolVar(&availOnly, "available", availOnly, "Only display available domain names.")
	flag.BoolVar(&regOnly, "registered", regOnly, "Only display registered domain names.")
}

func genEntries(parsed *tld.URL) {
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

func processEntry(arg async.Job) {
	entry := arg.(*Entry)
	entry.Available = available.Domain(entry.Domain)
	entry.Ascii, _ = idna.ToASCII(entry.Domain)
	// some whois might only be accepting ascii encoded domain names
	if entry.Available {
		entry.Available = available.Domain(entry.Ascii)
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

func main() {
	flag.Parse()

	// the tld library requires the schema or it won't parse the domain ¯\_(ツ)_/¯
	if !strings.Contains(url, "://") {
		url = fmt.Sprintf("https://%s", url)
	}

	parsed, err := tld.Parse(url)
	if err != nil {
		die("%v\n", err)
	} else if parsed.Domain == "" {
		die("could not parse %s\n", url)
	}

	genEntries(parsed)

	for _, entry := range entries {
		queue.Add(async.Job(entry))
	}

	fmt.Printf("checking %d variations for '%s.%s', please wait ...\n\n", len(entries), parsed.Domain, parsed.TLD)

	queue.WaitDone()

	for _, entry := range entries {
		if entry.Available {
			if !regOnly {
				fmt.Printf("%s (%s) : %s\n", entry.Domain, entry.Ascii, tui.Green("available"))
			}
		} else {
			if !availOnly {
				if len(entry.Addresses) == 0 {
					fmt.Printf("%s (%s) %s\n",
						entry.Domain,
						entry.Ascii,
						tui.Red("registered"))
				} else {
					fmt.Printf("%s (%s) %s : %s %s\n",
						entry.Domain,
						entry.Ascii,
						tui.Red("registered"),
						entry.Addresses,
						entry.Names)
				}
			}
		}
	}
}
