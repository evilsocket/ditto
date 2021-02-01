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
	Attributes []string `json:"what_changed"`
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

func structCompare(a, b interface{}) (bool, string) {
	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)
	nFieldsA := va.NumField()
	nFieldsB := vb.NumField()

	if nFieldsA != nFieldsB {
		return true, "num_fields"
	}

	for i := 0; i < nFieldsA; i++ {
		fieldA := va.Type().Field(i)
		fieldB := vb.Type().Field(i)
		if fieldA.Name != fieldB.Name {
			return true, fieldA.Name
		}

		fieldName := strings.ToLower(fieldA.Name)

		fieldValueA := va.Field(i)
		fieldValueB := vb.Field(i)

		if fieldValueA.Type() != fieldValueB.Type() {
			return true, fmt.Sprintf("%s.type", fieldName)
		}

		// same index, same name, same type, now let's check the value
		if reflect.DeepEqual(fieldValueA.Interface(), fieldValueB.Interface()) == false {
			return true, fieldName
		}
	}

	return false, ""
}

func contactCompare(a, b *whoisparser.Contact, prefix string) (bool, string) {
	if a == nil && b != nil {
		return true, prefix
	} else if a != nil && b == nil {
		return true, prefix
	} else if a == nil && b == nil {
		return false, ""
	}

	if changed, field := structCompare(*a, *b); changed {
		return true, fmt.Sprintf("%s.%s", prefix, field)
	}

	return false, ""
}

func fixArrays(d *whoisparser.Domain) {
	if len(d.Status) == 0 && d.Status != nil {
		d.Status = nil
	}
	if d.Status != nil {
		sort.Strings(d.Status)
	}
	if len(d.NameServers) == 0 && d.NameServers != nil {
		d.NameServers = nil
	}
	if d.NameServers != nil {
		sort.Strings(d.NameServers)
	}
}

func whoisCompare(a, b *whoisparser.WhoisInfo) (bool, string) {
	if a == nil && b != nil {
		return true, "whois"
	} else if a != nil && b == nil {
		return true, "whois"
	} else if a == nil && b == nil {
		return false, ""
	}

	if a.Domain == nil && b.Domain != nil {
		return true, "whois.domain"
	} else if a.Domain != nil && b.Domain == nil {
		return true, "whois.domain"
	} else if a.Domain != nil && b.Domain != nil {
		// since []string{} != nil for reflect.DeepEqual
		// we need to normalize
		fixArrays(a.Domain)
		fixArrays(b.Domain)

		if changed, field := structCompare(*a.Domain, *b.Domain); changed {
			return true, fmt.Sprintf("whois.domain.%s", field)
		}
	}

	if changed, what := contactCompare(a.Registrar, b.Registrar, "whois.registrar"); changed {
		return true, what
	} else if changed, what = contactCompare(a.Registrant, b.Registrant, "whois.registrant"); changed {
		return true, what
	} else if changed, what = contactCompare(a.Administrative, b.Administrative, "whois.administrative"); changed {
		return true, what
	} else if changed, what = contactCompare(a.Billing, b.Billing, "whois.billing"); changed {
		return true, what
	} else if changed, what = contactCompare(a.Technical, b.Technical, "whois.technical"); changed {
		return true, what
	}

	return false, ""
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
			d.Attributes = append(d.Attributes, "addresses")
		}

		if reflect.DeepEqual(prev.Names, curr.Names) == false {
			d.Attributes = append(d.Attributes, "names")
		}

		if changed, what := whoisCompare(prev.Whois, curr.Whois); changed {
			d.Attributes = append(d.Attributes, what)
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
			doTrigger := false
			for _, attrName := range deltas.Attributes() {
				if attrName == "addresses"  {
					doTrigger = !ignoreAddressChange
				} else if attrName == "names" {
					doTrigger = !ignoreNamesChange
				} else {
					doTrigger = true
				}

				if doTrigger {
					break
				}
			}

			if doTrigger {
				fmt.Printf("running trigger ...\n")
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
		}

		if !keepChanges {
			os.Remove(deltaFileName)
		}
	}
}
