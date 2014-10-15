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

// Package gonftnl wraps libnftnl, providing a low-level netlink
// programming interface (API) to the in-kernel nf_tables subsystem.
//
// gonftnl requires libnftnl, libmnl and a kernel that includes the nf_tables subsystem (initial support >= 3.14).
//
package nft

import (
	//	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

/*
#cgo linux LDFLAGS: -lnftnl -lmnl

#include <stdlib.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>

extern int go_table_callback(const struct nlmsghdr *nlh, void *data);
mnl_cb_t get_go_table_cb() {
        return (mnl_cb_t)go_table_callback;
}
*/
import "C"

// json wrapper
type jsonTable struct {
	Table Table `json:"table"`
}

type Table struct {
	Name   string `json:"name"`
	Family string `json:"family"`
	Use    uint32 `json:"use,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`

	table *C.struct_nft_table
}

type tableChan chan *Table

func (t *Table) String() string {
	return fmt.Sprintf("%s %s", t.Name, t.Family)
}

// Get a table by name
func GetTable(name string) (*Table, error) {
	tables, err := getTable(name)

	if len(tables) == 1 {
		return tables[0], err
	} else {
		return nil, err
	}
}

// Get all tables
func GetTables() ([]*Table, error) {
	return getTable("")
}

func getTable(name string) (tables []*Table, err error) {

	t := &Table{}
	t.table = C.nft_table_alloc()

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
			C.uint16_t(C.enum_nf_tables_msg_types(C.NFT_MSG_GETTABLE)),
			C.NFPROTO_IPV4,
			C.NLM_F_ACK,
			C.uint32_t(seq))

		cstring := C.CString(name)
		defer C.free(unsafe.Pointer(cstring))
		C.nft_table_attr_set(t.table, C.NFT_TABLE_ATTR_NAME, unsafe.Pointer(cstring))
		C.nft_table_nlmsg_build_payload(nlh, t.table)
	} else {
		nlh = C.nft_table_nlmsg_build_hdr(
			(*C.char)(unsafe.Pointer(&buf[0])),
			C.uint16_t(C.enum_nf_tables_msg_types(C.NFT_MSG_GETTABLE)),
			C.NFPROTO_IPV4,
			C.NLM_F_DUMP,
			C.uint32_t(seq))
	}
	if nlh == nil {
		err = fmt.Errorf("nft_table_nlmsg_build_hdr")
		return
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

	var cerr error
	var n C.int
	var sn C.ssize_t
	sn = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), (C.size_t)(len(buf)))
	tablech := make(tableChan)

	readyCh := make(chan bool, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readyCh <- true
		for {
			select {
			case t, ok := <-tablech:
				if ok {
					tables = append(tables, t)
				} else {
					return
				}
			}
		}
	}()
	<-readyCh

	for sn > 0 {
		n, cerr = C.mnl_cb_run(
			unsafe.Pointer(&buf[0]),
			C.size_t(sn),
			C.uint(seq), portid,
			C.mnl_cb_t(C.get_go_table_cb()),
			unsafe.Pointer(&tablech))

		sn = C.ssize_t(n)
		if sn <= 0 {
			break
		}
		sn, cerr = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}

	close(tablech)
	wg.Wait()

	if sn == -1 {
		err = fmt.Errorf("mnl_cb_run err %s", cerr)
		return
	}
	C.mnl_socket_close(nl)

	return
}
