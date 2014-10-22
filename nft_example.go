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

	chain := nft.Chain{}
	chain.Name = "input"

	rules, err := chain.GetRules()
	if err != nil {
		log.Fatalf("GetRules err %s", err)
	}

	log.Printf("%d rules returned", len(rules))
	for _, r := range rules {
		log.Printf("rule %s returned", r)
		//log.Printf("rule %v", r)
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
