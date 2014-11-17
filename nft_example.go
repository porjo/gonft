// +build ignore

package main

import (
	"log"
	//	"net"

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

	table, err := nft.GetTable("filter", "ip4")
	if err != nil {
		log.Fatalf("GetTable err %s", err)
	}

	log.Printf("table %s returned", table)

	tcf := nft.TCF{}
	tcf.Table.Name = "filter"
	//tcf.Chain.Name = "input"
	tcf.Chain.Name = "output"
	tcf.Family = "ip"

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

	rule := nft.Rule{}
	rule.Table = "filter"
	rule.Chain = "input"
	rule.Family = "ip"
	//rule.Handle = 5
	//rule.Position = 2
	rule.Proto = 6
	rule.SPort = 22
	/*
		rule.DAddr = &net.IPNet{}
		if _, rule.DAddr, err = net.ParseCIDR("192.168.1.1/24"); err != nil {
			return
		}

		if rule.OIf, err = net.InterfaceByName("p1p1"); err != nil {
			return
		}
	*/

	err = rule.AddJson2()
	if err != nil {
		log.Fatalf("Rule Add err %s", err)
	}
}
