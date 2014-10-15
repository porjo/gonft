// Copyright (C) 2014 Ian Bishop
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package nft

import (
	//	"fmt"
	"encoding/json"
	"strings"
	"unsafe"
)

/*
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
*/
import "C"

//export go_table_callback
func go_table_callback(nlh *C.struct_nlmsghdr, data unsafe.Pointer) int {
	t := &Table{}
	t.table = C.nft_table_alloc()

	if C.nft_table_nlmsg_parse(nlh, t.table) < 0 {
		return C.MNL_CB_ERROR
	}

	buf := make([]byte, 4096)
	outputType := C.NFT_OUTPUT_JSON
	C.nft_table_snprintf(
		(*C.char)(unsafe.Pointer(&buf[0])),
		4096,
		t.table,
		(C.uint32_t)(outputType),
		0)

	jtable := jsonTable{}
	jsonStr := string(buf)
	buf = []byte(strings.TrimRight(jsonStr, "\x00"))
	err := json.Unmarshal(buf, &jtable)
	if err != nil {
		return C.MNL_CB_ERROR
	}

	table := &jtable.Table

	tablech := (*tableChan)(data)
	*tablech <- table

	return C.MNL_CB_OK
}

//export go_rule_callback
func go_rule_callback(nlh *C.struct_nlmsghdr, data unsafe.Pointer) int {
	r := &Rule{}
	r.rule = C.nft_rule_alloc()

	if C.nft_rule_nlmsg_parse(nlh, r.rule) < 0 {
		return C.MNL_CB_ERROR
	}

	buf := make([]byte, 4096)
	outputType := C.NFT_OUTPUT_JSON
	C.nft_rule_snprintf(
		(*C.char)(unsafe.Pointer(&buf[0])),
		4096,
		r.rule,
		(C.uint32_t)(outputType),
		0)

	jrule := jsonRule{}
	jsonStr := string(buf)
	buf = []byte(strings.TrimRight(jsonStr, "\x00"))
	err := json.Unmarshal(buf, &jrule)
	if err != nil {
		return C.MNL_CB_ERROR
	}

	rule := &jrule.Rule

	rulech := (*ruleChan)(data)
	*rulech <- rule

	return C.MNL_CB_OK
}
