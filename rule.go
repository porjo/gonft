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
	//	"errors"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"
	"unsafe"
)

/*
#include <stdlib.h>
#include <netinet/in.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

extern int go_rule_callback(const struct nlmsghdr *nlh, void *data);
mnl_cb_t get_go_rule_cb() {
        return (mnl_cb_t)go_rule_callback;
}
*/
import "C"

// json wrapper
type jsonRule struct {
	Rule nftRule `json:"rule"`
}

type nftRule struct {
	Table       string `json:"table"`
	Chain       string `json:"chain"`
	Family      string `json:"family"`
	Handle      uint64 `json:"handle"`
	Position    uint64 `json:"position,omitempty"`
	CompatFlags uint32 `json:"compat_flags,omitempty"`
	CompatProto uint32 `json:"compat_proto,omitempty"`
	Expr        []struct {
		Type   string `json:"type,omitempty"`
		Dreg   int    `json:"dreg,omitempty"`
		Offset int    `json:"offset,omitempty"`
		Len    int    `json:"len,omitempty"`
		Base   string `json:"base,omitempty"`

		// Used by 'cmp'
		Sreg    int     `json:"sreg,omitempty"`
		Op      string  `json:"op,omitempty"`
		DataReg DataReg `json:"data_reg,omitempty"`

		// Used by 'meta'
		Key string `json:"key,omitempty"`

		// Used by 'counter'
		Packets uint64 `json:"pkts,omitempty"`
		Bytes   uint64 `json:"bytes,omitempty"`

		// Used by 'bitwise'
		Mask struct {
			DataReg DataReg `json:"data_reg,omitempty"`
		} `json:"mask,omitempty"`
		Xor struct {
			DataReg DataReg `json:"data_reg,omitempty"`
		} `json:"xor,omitempty"`
	}

	// Used to store C rule ptr temporarily
	rule *C.struct_nft_rule
}

// Used internally
type DataReg struct {
	Type    string `json:"type,omitempty"`
	Len     int    `json:"len,omitempty"`
	Data0   string `json:"data0,omitempty"`
	Data1   string `json:"data1,omitempty"`
	Data2   string `json:"data2,omitempty"`
	Data3   string `json:"data3,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

type Rule struct {
	Table    string
	Chain    string
	Family   string
	Position int
	Handle   int

	Proto   int
	DPort   int
	SPort   int
	Packets uint64
	Bytes   uint64

	DAddr net.IPNet
	SAddr net.IPNet

	//output interface
	OIf *net.Interface
	//input interface
	IIf *net.Interface

	Action string
}

// Get all rules for given TCF
func (x *TCF) GetRules() (rules []Rule, err error) {
	nrules, err := getRules(x.Table.Name, x.Chain.Name, x.Family)

	if err != nil {
		return
	}

	rules, err = rulesConvert(nrules)

	return
}

// convert libnft rules to gonft rules
func rulesConvert(nrules []nftRule) (rules []Rule, err error) {
	for _, nr := range nrules {

		r := &Rule{}
		r.Table = nr.Table
		r.Chain = nr.Chain
		r.Family = nr.Family
		r.Position = int(nr.Position)
		r.Handle = int(nr.Handle)

		for i := 0; i < len(nr.Expr); i++ {

			switch nr.Expr[i].Type {
			case "payload":
				if err = r.processPayload(nr, i); err != nil {
					return
				}
			case "counter":
				r.Packets = nr.Expr[i].Packets
				r.Bytes = nr.Expr[i].Bytes
			case "meta":
				if err = r.processMeta(nr, i); err != nil {
					return
				}
			case "immediate":
				r.Action = nr.Expr[i].DataReg.Verdict
			}
		}
		rules = append(rules, *r)
	}

	return
}

// process 'bitwise' expr
func (r *Rule) processBitwise(nr nftRule, idx int, dest bool) (err error) {
	if idx+1 >= len(nr.Expr) {
		err = fmt.Errorf("Index out of range %d", idx+1)
		return
	}

	var ip net.IP
	var mask net.IPMask

	if mask, err = datareg2IP(nr.Expr[idx].Mask.DataReg); err != nil {
		return
	}
	if ip, err = datareg2IP(nr.Expr[idx+1].DataReg); err != nil {
		return
	}

	if dest {
		r.DAddr.IP = ip
		r.DAddr.Mask = mask
	} else {
		r.SAddr.IP = ip
		r.SAddr.Mask = mask
	}

	return
}

// Return byte slice suitable for net.IP
func datareg2IP(dr DataReg) (data []byte, err error) {
	length := dr.Len

	switch length {
	// ip4
	case 4:
		if data, err = hex2bytes(dr.Data0); err != nil {
			return
		}
	// ip6
	case 16:
		var tmp []byte
		if tmp, err = hex2bytes(dr.Data0); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex2bytes(dr.Data1); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex2bytes(dr.Data2); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex2bytes(dr.Data3); err != nil {
			return
		}
		data = append(data, tmp...)
	}

	return
}

// convert 32bit hex string to byte slice
func hex2bytes(hex string) (b []byte, err error) {
	var mask uint64
	if hex == "" {
		err = fmt.Errorf("hex string empty")
		return
	}
	b = make([]byte, 4)
	mask, err = strconv.ParseUint(hex, 0, 32)
	if err != nil {
		return
	}

	binary.LittleEndian.PutUint32(b, uint32(mask))
	return
}

// process 'payload' expr
func (r *Rule) processPayload(nr nftRule, idx int) (err error) {
	var big uint64

	if idx+1 >= len(nr.Expr) {
		err = fmt.Errorf("Index out of range %d", idx+1)
		return
	}

	switch nr.Expr[idx].Base {
	case "network":

		if nr.Expr[idx+1].Type == "bitwise" {
			// src/dest address
			var dest bool
			if nr.Expr[idx].Offset == 16 {
				dest = true
			}
			err = r.processBitwise(nr, idx+1, dest)
			if err != nil {
				return
			}
		} else {
			// protocol e.g. tcp, udp
			hex := nr.Expr[idx+1].DataReg.Data0
			if hex == "" {
				err = fmt.Errorf("Data0 empty")
				return
			}
			length := nr.Expr[idx+1].DataReg.Len
			big, err = strconv.ParseUint(hex, 0, length*8)
			if err != nil {
				return
			}
			r.Proto = int(big)
		}
	case "transport":
		// src/dest port
		hex := nr.Expr[idx+1].DataReg.Data0
		if hex == "" {
			err = fmt.Errorf("Data0 empty")
			return
		}

		length := nr.Expr[idx+1].DataReg.Len
		data := make([]byte, length)
		big, err = strconv.ParseUint(hex, 0, length*8)
		if err != nil {
			return
		}

		binary.LittleEndian.PutUint16(data, uint16(big))

		var port uint16
		buf := bytes.NewBuffer(data)
		binary.Read(buf, binary.BigEndian, &port)

		switch nr.Expr[idx].Offset {
		case 1:
			r.SPort = int(port)
		case 2:
			r.DPort = int(port)
		}
	}
	return
}

// process 'meta' expr e.g. network interfaces
func (r *Rule) processMeta(nr nftRule, idx int) (err error) {
	var iface uint64

	if idx+1 >= len(nr.Expr) {
		err = fmt.Errorf("Index out of range %d", idx+1)
		return
	}

	length := nr.Expr[idx+1].DataReg.Len
	hex := nr.Expr[idx+1].DataReg.Data0
	if hex == "" {
		err = fmt.Errorf("Data0 empty")
		return
	}
	if iface, err = strconv.ParseUint(hex, 0, length*8); err != nil {
		return
	}

	switch nr.Expr[idx].Key {
	case "iif":
		if r.IIf, err = net.InterfaceByIndex(int(iface)); err != nil {
			return
		}
	case "oif":
		if r.OIf, err = net.InterfaceByIndex(int(iface)); err != nil {
			return
		}
	}
	return
}

/*
func (r Rule) String() string {
	return fmt.Sprintf("%s %s %s %d %d", r.Family, r.Table, r.Chain)
}
*/

/*
func GetRules6(chain string) ([]*Rule, error) {
	return getRule(chain, "ip6")
}
*/

func getRules(table, chain, family string) (rules []nftRule, err error) {
	var ok bool
	var f, bufsize int
	var cerr error
	var n C.int
	var sn C.ssize_t

	if f, ok = familyMap[family]; !ok {
		err = fmt.Errorf("unrecognised family %s", family)
		return
	}

	r := C.nft_rule_alloc()
	defer C.free(unsafe.Pointer(r))

	seq := time.Time{}.Unix()

	// The following const was not recognised from libmnl.h
	// #define MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
	if C.getpagesize() < 8192 {
		bufsize = int(C.getpagesize())
	} else {
		bufsize = 8192
	}
	buf := make([]byte, bufsize)
	nlh := C.nft_rule_nlmsg_build_hdr(
		(*C.char)(unsafe.Pointer(&buf[0])),
		C.uint16_t(C.enum_nf_tables_msg_types(C.NFT_MSG_GETRULE)),
		C.uint16_t(f),
		C.NLM_F_DUMP,
		C.uint32_t(seq))

	if nlh == nil {
		err = fmt.Errorf("nft_rule_nlmsg_build_hdr")
		return
	}

	C.nft_rule_nlmsg_build_payload(nlh, r)

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

	if C.mnl_socket_sendto(nl, unsafe.Pointer(nlh), C.size_t(nlh.nlmsg_len)) < 0 {
		err = fmt.Errorf("mnl_socket_sendto")
		return
	}

	sn, cerr = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if sn == -1 {
		err = fmt.Errorf("mnl_socket_recvfrom: err %s", cerr)
		return
	}

	for sn > 0 {
		n, cerr = C.mnl_cb_run(
			unsafe.Pointer(&buf[0]),
			C.size_t(sn),
			C.uint(seq),
			portid,
			C.mnl_cb_t(C.get_go_rule_cb()),
			unsafe.Pointer(&rules))

		sn = C.ssize_t(n)
		if sn <= 0 {
			break
		}
		sn, cerr = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}

	if sn == -1 {
		err = fmt.Errorf("mnl_cb_run: err %s", cerr)
		return
	}
	C.mnl_socket_close(nl)

	//filter out extraneous rules
	var newRules []nftRule
	for _, r := range rules {
		if r.Table == table && r.Chain == chain {
			newRules = append(newRules, r)
		}
	}

	rules = newRules

	return
}

func AddJson() (err error) {
	var rules []nftRule
	rules, err = getRules("filter", "input", "ip4")

	if len(rules) == 0 {
		err = fmt.Errorf("no rules returned")
		return
	}

	rule := rules[0]

	for i, _ := range rule.Expr {
		if rule.Expr[i].DataReg.Data0 == "0x00000006" { //tcp
			rule.Expr[i].DataReg.Data0 = "0x00000011" //udp (hex)
		}
	}

	var cerr error
	var n C.int
	var r *C.struct_nft_rule

	r, cerr = C.nft_rule_alloc()
	if r == nil {
		err = fmt.Errorf("rule alloc failure: %s", cerr)
		return
	}
	defer C.free(unsafe.Pointer(r))

	var buf []byte
	buf, err = json.Marshal(rule)

	var parseErr C.struct_nft_parse_err
	n, cerr = C.nft_rule_parse(
		r,
		C.enum_nft_parse_type(C.NFT_PARSE_JSON),
		(*C.char)(unsafe.Pointer(&buf[0])),
		&parseErr,
	)

	fmt.Printf("nft_rule_parse r %v, n %d, buf %s, parseErr %v, cerr %s\n", r, n, buf, parseErr, cerr)

	return
}
