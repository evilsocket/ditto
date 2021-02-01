package main

import (
	"flag"
	"fmt"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/evilsocket/islazy/async"
	"github.com/evilsocket/islazy/fs"
	tld "github.com/jpillora/go-tld"
	"golang.org/x/net/idna"
	"os"
	"strings"
	"time"
)

var (
	aString             = ""
	url                 = ""
	parsed              = (* tld.URL)(nil)
	err                 = (error)(nil)
	limit               = 0
	queue               = async.NewQueue(1, processEntry)
	throttle            = 500
	numWorkers          = 1
	progress            = (* pb.ProgressBar)(nil)
	quiet               = false
	silent              = false
	mutateTLD           = false
	availOnly           = false
	regOnly             = false
	liveOnly            = false
	whoisInfo           = false
	csvFileName         = ""
	testDataFile        = ""
	monitorPeriodString = ""
	monitorPeriod       = time.Duration(0)
	monitorPath         = "/tmp"
	keepChanges         = false
	triggerCommand      = ""
	ignoreAddressChange = false
	ignoreNamesChange   = false
	noProgressBar       = false
	swarmMode           = false
)

func die(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func init() {
	flag.StringVar(&aString, "string", aString, "Generate variations of a string.")
	flag.StringVar(&url, "domain", url, "Domain name or url.")
	flag.IntVar(&limit, "limit", limit, "Limit the number of permutations.")
	flag.IntVar(&throttle, "throttle", throttle, "Throttle requests by a given amount of milliseconds.")
	flag.IntVar(&numWorkers, "workers", numWorkers, "Number of concurrent workers, set to 0 to use one per logical CPU core.")
	flag.BoolVar(&quiet, "quiet", quiet, "Don't show results on terminal.")
	flag.BoolVar(&silent, "silent", silent, "Suppress all terminal output.")
	flag.BoolVar(&mutateTLD, "tld", mutateTLD, "Try different permutations by replacing the TLD.")
	flag.BoolVar(&availOnly, "available", availOnly, "Only display available domain names.")
	flag.BoolVar(&regOnly, "registered", regOnly, "Only display registered domain names.")
	flag.BoolVar(&liveOnly, "live", liveOnly, "Only display registered domain names that also resolve to an IP.")
	flag.BoolVar(&whoisInfo, "whois", whoisInfo, "Show whois information.")
	flag.StringVar(&csvFileName, "csv", csvFileName, "If set ditto will save results to this CSV file.")

	flag.StringVar(&testDataFile, "test-data", testDataFile, "Used for testing purposes, load test data from a JSON file.")

	flag.StringVar(&monitorPeriodString, "monitor", monitorPeriodString, "If specified will monitor for changes with the specified period.")

	flag.StringVar(&monitorPath, "changes", monitorPath, "Base path to save changes files into.")
	flag.BoolVar(&keepChanges, "keep-changes", keepChanges, "Do not remove changes JSON files.")

	flag.BoolVar(&ignoreAddressChange, "ignore-ip-changes", ignoreAddressChange, "Do not trigger for IP address changes.")
	flag.BoolVar(&ignoreNamesChange, "ignore-host-changes", ignoreNamesChange, "Do not trigger for hostname changes.")
	flag.StringVar(&triggerCommand, "trigger", triggerCommand, "Command to run when in monitor mode and one or more domains changed.")

	flag.BoolVar(&noProgressBar, "no-progress-bar", noProgressBar, "Do not show the progress bar.")

	flag.BoolVar(&swarmMode, "swarm", swarmMode,
		"In swarm mode -domain will be parsed as a comma separated list of domains and a ditto process will be"+
			" spawned for each one, copying the arguments of the main process.")
}

func main() {
	flag.Parse()

	if aString != "" {
		for _, perm := range genEntriesForString(aString) {
			ascii, err := idna.ToASCII(perm)
			if err != nil {
				ascii = err.Error()
			}

			fmt.Printf("%s (%s)\n", perm, ascii)
		}
		return
	}

	if url == "" {
		fmt.Printf("no -domain specified.\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if swarmMode {
		swarmMain()
		return
	}

	// the tld library requires the schema or it won't parse the domain ¯\_(ツ)_/¯
	if !strings.Contains(url, "://") {
		url = fmt.Sprintf("https://%s", url)
	}

	parsed, err = tld.Parse(url)
	if err != nil {
		die("could not parse '%s': %v\n", url, err)
	} else if parsed.Domain == "" {
		die("could not parse %s\n", url)
	}

	if monitorPeriodString != "" {
		if monitorPeriod, err = time.ParseDuration(monitorPeriodString); err != nil {
			die("could not parse period '%s': %v\n", monitorPeriodString, err)
		}

		if !fs.Exists(monitorPath) {
			if err = os.MkdirAll(monitorPath, os.ModePerm); err != nil {
				die("could not create '%s': %v\n", monitorPath, err)
			}
		}
	}

	for {
		updateEntries(parsed)

		// if in monitor mode, it's the first run and we want to keep the changes ond disk
		// save a file with the initial status of this domain
		if monitorPeriod != 0 && prevEntries == nil && keepChanges {
			if err = saveState(); err != nil {
				die("%s\n", err)
			}
		}

		if monitorPeriod == 0 || prevEntries == nil {
			printEntries()
		} else if monitorPeriod != 0 {
			monitorDeltas()
		}

		csvSaveIfNeeded()

		if monitorPeriod == 0 {
			return
		} else {
			time.Sleep(monitorPeriod)
		}
	}
}
