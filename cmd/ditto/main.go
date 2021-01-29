package main

import (
	"flag"
	"fmt"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/evilsocket/islazy/async"
	tld "github.com/jpillora/go-tld"
	"github.com/likexian/whois-parser-go"
	"golang.org/x/net/idna"
	"os"
	"strings"
)

type Entry struct {
	Domain    string
	Ascii     string
	Available bool
	Whois     *whoisparser.WhoisInfo
	Addresses []string
	Names     []string
}

var (
	aString     = ""
	url         = "https://www.ice.gov"
	limit       = 0
	entries     = make([]*Entry, 0)
	queue       = async.NewQueue(0, processEntry)
	progress    = (* pb.ProgressBar)(nil)
	availOnly   = false
	regOnly     = false
	liveOnly    = false
	whoisInfo   = false
	csvFileName = ""
)

func die(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func init() {
	flag.StringVar(&aString, "string", aString, "Generate variations of a string.")
	flag.StringVar(&url, "domain", url, "Domain name or url.")
	flag.IntVar(&limit, "limit", limit, "Limit the number of permutations.")
	flag.BoolVar(&availOnly, "available", availOnly, "Only display available domain names.")
	flag.BoolVar(&regOnly, "registered", regOnly, "Only display registered domain names.")
	flag.BoolVar(&liveOnly, "live", liveOnly, "Only display registered domain names that also resolve to an IP.")
	flag.BoolVar(&whoisInfo, "whois", whoisInfo, "Show whois information.")
	flag.StringVar(&csvFileName, "csv", csvFileName, "If set ditto will save results to this CSV file.")
}

func main() {
	flag.Parse()

	if aString != "" {
		for _, perm := range genEntriesForString(aString) {
			ascii, err := idna.ToASCII(perm)
			if err != nil{
				ascii = err.Error()
			}

			fmt.Printf("%s (%s)\n", perm, ascii)
		}

		return
	}

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

	fmt.Printf("checking %d variations for '%s.%s', please wait ...\n\n", len(entries), parsed.Domain, parsed.TLD)

	progress = pb.StartNew(len(entries))

	for _, entry := range entries {
		queue.Add(async.Job(entry))
	}

	queue.WaitDone()

	progress.Finish()

	fmt.Printf("\n\n")

	for _, entry := range entries {
		printEntry(entry)
	}

	if csvFileName != "" {
		fmt.Printf("\n\n")
		csvSave()
	}
}
