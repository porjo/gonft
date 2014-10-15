// +build ignore

package main

import (
	"log"

	nft "github.com/porjo/gonft"
)

func main() {

	var err error

	tables, err := nft.GetTables()
	if err != nil {
		log.Fatal(err)
	}

	if len(tables) == 0 {
		log.Fatal("no tables returned")
	} else {
		for _, t := range tables {
			log.Printf("table %s returned", t)
			log.Printf("table %#v", t)
		}
	}

	table, err := nft.GetTable("filter")
	if err != nil {
		log.Fatal(err)
	}

	if table == nil {
		log.Fatal("no table returned")
	} else {
		log.Printf("table %s returned", table)
	}

	rules, err := nft.GetRules("input")
	if err != nil {
		log.Fatal(err)
	}
	if len(rules) == 0 {
		log.Printf("no rules returned")
	} else {
		for _, r := range rules {
			log.Printf("rule %s returned", r)
			log.Printf("rule %#v", r)
		}
	}
}
