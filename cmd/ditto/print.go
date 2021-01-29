package main

import (
	"fmt"
	"github.com/evilsocket/islazy/tui"
	"strings"
)

func asString(entry *Entry) string {
	if entry.Domain != entry.Ascii {
		return fmt.Sprintf("%s (%s)", entry.Domain, entry.Ascii)
	}
	return entry.Domain
}

func printEntry(entry *Entry) {
	if entry.Available {
		if !regOnly && !liveOnly {
			fmt.Printf("%s : %s\n", asString(entry), tui.Green("available"))
		}
	} else {
		if !availOnly {
			mainFields := []string{}
			whoisFields := []string{}
			isLive := len(entry.Addresses) > 0

			if isLive {
				mainFields = append(mainFields, fmt.Sprintf("ips=%s", strings.Join(entry.Addresses, ",")))
				if len(entry.Names) > 0 {
					mainFields = append(mainFields, fmt.Sprintf("names=%s", strings.Join(entry.Names, ",")))
				}
			}

			if entry.Whois != nil {
				if entry.Whois.Registrar != nil {
					whoisFields = append(whoisFields, fmt.Sprintf("registrar=%s", entry.Whois.Registrar.ReferralURL))
				}

				if entry.Whois.Domain != nil {
					whoisFields = append(whoisFields, fmt.Sprintf("created=%s", entry.Whois.Domain.CreatedDate))
					whoisFields = append(whoisFields, fmt.Sprintf("updated=%s", entry.Whois.Domain.UpdatedDate))
					whoisFields = append(whoisFields, fmt.Sprintf("expires=%s", entry.Whois.Domain.ExpirationDate))
					whoisFields = append(whoisFields, fmt.Sprintf("ns=%s", strings.Join(entry.Whois.Domain.NameServers, ",")))
				}
			}

			if isLive || !liveOnly {
				fmt.Printf("%s %s",
					asString(entry),
					tui.Red("registered"))

				if len(mainFields) > 0 {
					fmt.Printf(" : %s", strings.Join(mainFields, " "))
				}

				fmt.Println()

				if whoisInfo && len(whoisFields) > 0 {
					for _, field := range whoisFields {
						fmt.Printf("  %s\n", field)
					}
					// raw, _ := json.MarshalIndent(entry.Whois, "", " ")
					// fmt.Printf("%s\n", string(raw))
				}
			}
		}
	}
}
