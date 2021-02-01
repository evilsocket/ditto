package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/evilsocket/islazy/str"
	whoisparser "github.com/likexian/whois-parser-go"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"reflect"
	"sort"
	"strings"
	"text/template"
	"time"
)

type Change struct {
	Attributes []string `json:"changes"`
	Old        *Entry   `json:"before"`
	New        *Entry   `json:"after"`
}

type Event struct {
	CheckedAt time.Time `json:"checked_at"`
	Changes   []Change  `json:"changes"`
}

func (e Event) Attributes() []string {
	list := make([]string, 0)
	uniq := make(map[string]bool, 0)

	for _, c := range e.Changes {
		for _, a := range c.Attributes {
			uniq[a] = true
		}
	}

	for a, _ := range uniq {
		list = append(list, a)
	}

	sort.Strings(list)

	return list
}

// use json to avoid checking pointers and comparing
// field by fielnd
func sameWhois(a, b *whoisparser.WhoisInfo) bool {
	if rawA, err := json.Marshal(a); err != nil {
		return false
	} else if rawB, err := json.Marshal(b); err != nil {
		return false
	} else {
		return bytes.Equal(rawA, rawB)
	}
}

func checkChanges() Event {
	changeEvent := Event{
		CheckedAt: time.Now(),
	}

	// domains are always in the same order
	for i := range entries {
		prev := prevEntries[i]
		curr := entries[i]
		d := Change{
			Old: prev,
			New: curr,
		}

		if prev.Available != curr.Available {
			d.Attributes = append(d.Attributes, "availability")
		}

		if reflect.DeepEqual(prev.Addresses, curr.Addresses) == false {
			// don't ignore if there weren't any addresses before
			if len(prev.Addresses) == 0 || !ignoreAddressChange {
				d.Attributes = append(d.Attributes, "addresses")
			}
		}

		if reflect.DeepEqual(prev.Names, curr.Names) == false {
			// don't ignore if there weren't any names before
			if len(prev.Names) == 0 || !ignoreNamesChange {
				d.Attributes = append(d.Attributes, "names")
			}

		}

		if sameWhois(prev.Whois, curr.Whois) == false {
			d.Attributes = append(d.Attributes, "whois")
		}

		if len(d.Attributes) > 0 {
			changeEvent.Changes = append(changeEvent.Changes, d)
		}
	}

	return changeEvent
}

type triggerData struct {
	Domain      string
	ChangesFile string
}

func monitorDeltas() {
	deltas := checkChanges()

	numChangedEntries := len(deltas.Changes)

	printChanges(deltas)

	if numChangedEntries > 0 {
		// fmt.Sprintf("%s.%s.json", parsed.Domain, parsed.TLD)
		fileName := fmt.Sprintf("%s.%s-changes-%d.json", parsed.Domain, parsed.TLD, deltas.CheckedAt.Unix())
		deltaFileName := path.Join(monitorPath, fileName)
		// do we need to dump the changes on file?
		if keepChanges || triggerCommand != "" {
			raw, err := json.MarshalIndent(deltas, "", "  ")
			if err != nil {
				die("error encoding changes to %s: %v\n", deltaFileName, err)
			} else if err = ioutil.WriteFile(deltaFileName, raw, os.ModePerm); err != nil {
				die("error saving changes to %s: %v\n", deltaFileName, err)
			}
		}

		if triggerCommand != "" {
			tpl, err := template.New("changes").Parse(triggerCommand)
			if err != nil {
				die("error parsing trigger command: %v\n", err)
			}

			var buf bytes.Buffer

			err = tpl.Execute(&buf, triggerData{
				Domain:      parsed.Host,
				ChangesFile: deltaFileName,
			})
			if err != nil {
				die("error parsing trigger command: %v\n", err)
			}

			command := buf.String()
			split := strings.Fields(command)

			cmd := exec.Command(split[0], split[1:]...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				die("error running trigger command '%s': %v\n", command, err)
			} else if len(output) > 0 && !silent {
				fmt.Printf("%s\n", str.Trim(string(output)))
			} else if !silent {
				// fmt.Printf("trigger executed.")
			}
		}

		if !keepChanges {
			os.Remove(deltaFileName)
		}
	}
}
