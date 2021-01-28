package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

func csvSave() {
	file, err := os.Create(csvFileName)
	if err != nil {
		die("error creating %s: %v\n", csvFileName, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	columns := []string {
		"unicode",
		"ascii",
		"status",
		"ips",
		"names",
	}

	if whoisInfo {
		columns = append(columns, []string{
			"registrar",
			"created_at",
			"updated_at",
			"expires_at",
			"nameservers",
		}...)
	}

	if err = writer.Write(columns); err != nil {
		die("error writing header: %v\n", err)
	}

	for _, entry := range entries {
		row := []string{
			entry.Domain,
			entry.Ascii,
		}

		if entry.Available {
			row = append(row, "available")
		} else {
			row = append(row, "registered")
		}

		row = append(row, strings.Join(entry.Addresses, ","))
		row = append(row, strings.Join(entry.Names, ","))

		if whoisInfo {
			if entry.Whois != nil {
				if entry.Whois.Registrar != nil {
					row = append(row, entry.Whois.Registrar.ReferralURL)
				} else {
					row = append(row, "")
				}

				if entry.Whois.Domain != nil {
					row = append(row, entry.Whois.Domain.CreatedDate)
					row = append(row, entry.Whois.Domain.UpdatedDate)
					row = append(row, entry.Whois.Domain.ExpirationDate)
					row = append(row, strings.Join(entry.Whois.Domain.NameServers, ","))
				} else {
					row = append(row, []string{
						"", "", "", ""}...)
				}
			} else {
				row = append(row, []string{
					"", "", "", "", ""}...)
			}
		}

		if err = writer.Write(row); err != nil {
			die("error writing line: %v\n", err)
		}
	}

	fmt.Printf("saved to %s\n", csvFileName)
}
