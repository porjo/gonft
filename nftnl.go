// Copyright (c) 2014 Ian Bishop
// Distributable under the terms of The New BSD License
// that can be found in the LICENSE file.

// Package gonftnl wraps libnftnl, providing a low-level netlink
// programming interface (API) to the in-kernel nf_tables subsystem.
//
// gonftnl requires libnftnl, libmnl and a kernel that includes the nf_tables subsystem (initial support >= 3.14).
//
package nftnl

import (
	//	"errors"
	"fmt"
	"time"
	"unsafe"
)

/*
#cgo linux LDFLAGS: -lnftnl

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

//#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
//#define _MNL_SOCKET_BUFFER_SIZE 500
#define _MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
*/
import "C"

type Table struct {
	table *C.struct_nft_table
}

func NewTable() (t *Table) {
	t = &Table{}
	t.table = C.nft_table_alloc()
	return
}

func (t *Table) Close() {
	C.nft_table_free(t.table)
}

func (t *Table) GetName(name string) {

	seq := time.Time{}.Unix()

	// The following was not being recognised from libmnl.h
	// #define MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
	var bufsize int
	if C.getpagesize() < 8192 {
		bufsize = int(C.getpagesize())
	} else {
		bufsize = 8192
	}
	buf := make([]byte, bufsize)
	var nlh *C.struct_nlmsghdr
	nlh = C.nft_table_nlmsg_build_hdr(
		(*C.char)(unsafe.Pointer(&buf[0])),
		(C.uint16_t)(C.enum_nf_tables_msg_types(C.NFT_MSG_GETTABLE)),
		C.NFPROTO_IPV4,
		C.NLM_F_ACK,
		(C.uint32_t)(seq))

	fmt.Printf("name %s, nlh %v", name, nlh)

	cstring := C.CString(name)
	defer C.free(unsafe.Pointer(cstring))
	C.nft_table_attr_set(t.table, C.NFT_TABLE_ATTR_NAME, unsafe.Pointer(cstring))
	//nft_table_nlmsg_build_payload(nlh, t)
	//nft_table_free(t)
}
