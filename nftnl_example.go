// +build ignore

package main

import (
	"log"

	nftnl "github.com/porjo/gonftnl"
)

var table *nftnl.Table

func main() {

	table = nftnl.NewTable()

	if table == nil {
		log.Fatal("Expected non-nil result")
	}

	//err := table.GetName("blah")
	err := table.GetName("")
	if err != nil {
		log.Fatal(err)
	}
	table.Close()
}
