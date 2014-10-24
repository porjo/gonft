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
	"encoding/json"
	"log"
	"strings"
	"unsafe"
)

/*
#include <stdlib.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
*/
import "C"

//export go_table_callback
func go_table_callback(nlh *C.struct_nlmsghdr, data unsafe.Pointer) int {
	t := C.nft_table_alloc()
	defer C.free(unsafe.Pointer(t))

	if C.nft_table_nlmsg_parse(nlh, t) < 0 {
		return C.MNL_CB_ERROR
	}

	buf := make([]byte, 4096)
	outputType := C.NFT_OUTPUT_JSON
	C.nft_table_snprintf(
		(*C.char)(unsafe.Pointer(&buf[0])),
		4096,
		t,
		C.uint32_t(outputType),
		0)

	jtable := jsonTable{}
	jsonStr := string(buf)
	buf = []byte(strings.TrimRight(jsonStr, "\x00"))
	err := json.Unmarshal(buf, &jtable)
	if err != nil {
		return C.MNL_CB_ERROR
	}

	tables := (*[]Table)(data)
	*tables = append(*tables, jtable.Table)

	return C.MNL_CB_OK
}

//export go_rule_callback
func go_rule_callback(nlh *C.struct_nlmsghdr, data unsafe.Pointer) int {
	r := C.nft_rule_alloc()
	defer C.free(unsafe.Pointer(r))

	if n, cerr := C.nft_rule_nlmsg_parse(nlh, r); n < 0 {
		log.Printf("nft_rule_nlmsg_parse err %s", cerr)
		return C.MNL_CB_ERROR
	}

	buf := make([]byte, 4096)
	outputType := C.NFT_OUTPUT_JSON
	C.nft_rule_snprintf(
		(*C.char)(unsafe.Pointer(&buf[0])),
		4096,
		r,
		C.uint32_t(outputType),
		0,
	)

	jrule := jsonRule{}
	jsonStr := string(buf)
	buf = []byte(strings.TrimRight(jsonStr, "\x00"))
	err := json.Unmarshal(buf, &jrule)
	if err != nil {
		log.Printf("json unmarshal error %s", err)
		return C.MNL_CB_ERROR
	}

	//log.Printf("rule json %s\n", buf)

	rules := (*[]nftRule)(data)
	*rules = append(*rules, jrule.Rule)

	return C.MNL_CB_OK
}
