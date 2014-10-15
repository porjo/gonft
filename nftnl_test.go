package nftnl

import (
	"testing"
)

var table *Table

func TestNewTable(t *testing.T) {

	table = NewTable()

	if table == nil {
		t.Fatalf("Expected non-nil result")
	}

	//table.Close()
}

func TestGetName(t *testing.T) {

	//err := table.GetName("blah")
	err := table.GetName("")
	if err != nil {
		t.Fatal(err)
	}
}
