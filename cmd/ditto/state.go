package main

import (
	"encoding/json"
	"fmt"
	whoisparser "github.com/likexian/whois-parser-go"
	"io/ioutil"
	"os"
	"path"
	"time"
)

var (
	entries     = []*Entry(nil)
	prevEntries = []*Entry(nil)
)

type Entry struct {
	Domain    string                 `json:"domain"`
	Ascii     string                 `json:"ascii"`
	Available bool                   `json:"available"`
	Whois     *whoisparser.WhoisInfo `json:"whois"`
	Addresses []string               `json:"addresses"`
	Names     []string               `json:"names"`
}

type State struct {
	Time    time.Time `json:"time"`
	Domain  string    `json:"domain"`
	Entries []*Entry  `json:"entries"`
}

func makeState() State {
	return State{
		Time:    time.Now(),
		Domain:  fmt.Sprintf("%s.%s", parsed.Domain, parsed.TLD),
		Entries: entries,
	}
}

func saveState() error {
	state := makeState()
	fileName := path.Join(monitorPath, fmt.Sprintf("%s.json", state.Domain))
	if raw, err := json.Marshal(state); err != nil {
		return fmt.Errorf("can't encode state: %v", err)
	} else if err = ioutil.WriteFile(fileName, raw, os.ModePerm); err != nil {
		return fmt.Errorf("error writing to %s: %v", fileName, raw)
	}
	return nil
}
