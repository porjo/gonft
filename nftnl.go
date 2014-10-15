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
#cgo linux LDFLAGS: -lnftnl -lmnl

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>

extern int go_callback(const struct nlmsghdr *nlh, void *data);
mnl_cb_t get_go_cb() {
        return (mnl_cb_t)go_callback;
}
*/
import "C"

type Table struct {
	table *C.struct_nft_table
}

type ReadAsyncCb_T func(*C.struct_nlmsghdr, uint32) int

var clientCb ReadAsyncCb_T

func NewTable() (t *Table) {
	t = &Table{}
	t.table = C.nft_table_alloc()
	return
}

func (t *Table) Close() {
	C.nft_table_free(t.table)
	t.table = nil
}

// Get table by name. If name is empty, then all tables are returned
// ref: http://git.netfilter.org/libnftnl/tree/examples/nft-table-get.c
func (t *Table) GetName(name string) (err error) {

	if t.table == nil {
		err = fmt.Errorf("table not initialized")
		return
	}

	seq := time.Time{}.Unix()

	// The following const was not recognised from libmnl.h
	// #define MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
	var bufsize int
	if C.getpagesize() < 8192 {
		bufsize = int(C.getpagesize())
	} else {
		bufsize = 8192
	}
	buf := make([]byte, bufsize)
	var nlh *C.struct_nlmsghdr
	if name != "" {
		nlh = C.nft_table_nlmsg_build_hdr(
			(*C.char)(unsafe.Pointer(&buf[0])),
			(C.uint16_t)(C.enum_nf_tables_msg_types(C.NFT_MSG_GETTABLE)),
			C.NFPROTO_IPV4,
			C.NLM_F_ACK,
			(C.uint32_t)(seq))

		cstring := C.CString(name)
		defer C.free(unsafe.Pointer(cstring))
		C.nft_table_attr_set(t.table, C.NFT_TABLE_ATTR_NAME, unsafe.Pointer(cstring))
		C.nft_table_nlmsg_build_payload(nlh, t.table)
		t.Close()
	} else {
		nlh = C.nft_table_nlmsg_build_hdr(
			(*C.char)(unsafe.Pointer(&buf[0])),
			(C.uint16_t)(C.enum_nf_tables_msg_types(C.NFT_MSG_GETTABLE)),
			C.NFPROTO_IPV4,
			C.NLM_F_DUMP,
			(C.uint32_t)(seq))
	}

	nl := C.mnl_socket_open(C.NETLINK_NETFILTER)
	if nl == nil {
		err = fmt.Errorf("mnl_socket_open")
		return
	}
	if C.mnl_socket_bind(nl, 0, C.MNL_SOCKET_AUTOPID) < 0 {
		err = fmt.Errorf("mnl_socket_bind")
		return
	}
	portid := C.mnl_socket_get_portid(nl)

	if C.mnl_socket_sendto(nl, unsafe.Pointer(nlh), (C.size_t)(nlh.nlmsg_len)) < 0 {
		err = fmt.Errorf("mnl_socket_send")
		return
	}

	ret := C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), (C.size_t)(len(buf)))
	outputType := uint32(C.NFT_OUTPUT_DEFAULT)
	for ret > 0 {
		ret = (C.ssize_t)(C.mnl_cb_run(
			unsafe.Pointer(&buf[0]),
			(C.size_t)(ret),
			(C.uint)(seq), portid,
			(C.mnl_cb_t)(C.get_go_cb()),
			unsafe.Pointer(&outputType)))
		if ret <= 0 {
			break
		}
		ret = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), (C.size_t)(len(buf)))
	}
	if ret == -1 {
		err = fmt.Errorf("mnl_cb_run err %d", ret)
		return
	}
	C.mnl_socket_close(nl)

	return
}
