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
		log.Fatalf("GetTables err %s", err)
	}

	if len(tables) == 0 {
		log.Fatal("no tables returned")
	} else {
		for _, t := range tables {
			log.Printf("table %s returned", t)
			log.Printf("table %#v", t)
		}
	}

	table, err := nft.GetTable("filter", "ip6")
	if err != nil {
		log.Fatalf("GetTable err %s", err)
	}

	log.Printf("table %s returned", table)

	tcf := nft.TCF{}
	tcf.Table.Name = "filter"
	tcf.Chain.Name = "input"
	tcf.Family = "ip6"

	rules, err := tcf.GetRules()
	if err != nil {
		log.Fatalf("GetRules err %s", err)
	}

	log.Printf("%d rules returned", len(rules))
	for _, r := range rules {
		log.Printf("rule %v returned", r)

		if r.IIf != nil {
			log.Printf("rule iff %#v", r.IIf)
		}
	}

	//nft.AddJson()
	/*
		rule := nft.Rule{}
		rule.Table = "filter"
		rule.Chain = "input"
		rule.Family = "ip4"

		err = rule.Add()
		if err != nil {
			log.Fatalf("Rule Add err %s", err)
		}
	*/
}
