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
	//	"bytes"
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
	Handle      uint64 `json:"handle,omitempty"`
	Position    uint64 `json:"position,omitempty"`
	CompatFlags uint32 `json:"compat_flags,omitempty"`
	CompatProto uint32 `json:"compat_proto,omitempty"`

	Expr []expr `json:"expr"`

	// Used to store C rule ptr temporarily
	rule *C.struct_nft_rule
}

type expr struct {
	Type   string `json:"type,omitempty"`
	Dreg   int    `json:"dreg,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Len    int    `json:"len,omitempty"`
	Base   string `json:"base,omitempty"`

	// Used by 'cmp'
	Sreg int    `json:"sreg,omitempty"`
	Op   string `json:"op,omitempty"`
	Data *data  `json:"data,omitempty"`

	// Used by 'meta'
	Key string `json:"key,omitempty"`

	// Used by 'counter'
	Packets uint64 `json:"pkts,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`

	// Used by 'bitwise'
	Mask *mask `json:"mask,omitempty"`
	Xor  *xor  `json:"xor,omitempty"`
}

type data struct {
	Reg reg `json:"reg,omitempty"`
}

type reg struct {
	Type    string `json:"type,omitempty"`
	Len     int    `json:"len,omitempty"`
	Data0   string `json:"data0,omitempty"`
	Data1   string `json:"data1,omitempty"`
	Data2   string `json:"data2,omitempty"`
	Data3   string `json:"data3,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

type mask struct {
	Reg reg `json:"reg,omitempty"`
}

type xor struct {
	Reg reg `json:"reg,omitempty"`
}

type Rule struct {
	Table    string
	Chain    string
	Family   string
	Position uint64
	Handle   uint64

	Proto   int
	DPort   int
	SPort   int
	Packets uint64
	Bytes   uint64

	DAddr *net.IPNet
	SAddr *net.IPNet

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

	rules, err = rulesNft2Go(nrules)

	return
}

// convert libnft rules to gonft rules
func rulesNft2Go(nrules []nftRule) (rules []Rule, err error) {
	for _, nr := range nrules {

		r := &Rule{}
		r.Table = nr.Table
		r.Chain = nr.Chain
		r.Family = nr.Family
		r.Position = nr.Position
		r.Handle = nr.Handle

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
				r.Action = nr.Expr[i].Data.Reg.Verdict
			}
		}
		rules = append(rules, *r)
	}

	return
}

func ruleGo2Nft(r Rule) (nr nftRule, err error) {
	var e expr

	nr.Table = r.Table
	nr.Chain = r.Chain
	nr.Family = r.Family
	if nr.Position != 0 {
		nr.Position = r.Position
	}

	if nr.Handle != 0 {
		nr.Handle = r.Handle
	}

	if (r.DPort != 0 || r.SPort != 0) && r.Proto == 0 {
		err = fmt.Errorf("Protocol must be specified with src/dst port")
		return
	}

	if r.Proto != 0 {

		e = expr{}
		e.Type = "payload"
		e.Dreg = 1
		e.Offset = 9
		e.Len = 1
		e.Base = "network"

		nr.Expr = append(nr.Expr, e)

		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(r.Proto))
		data0 := fmt.Sprintf("0x%x", data)
		if err = (&nr).processCmp(1, data0, "", "", ""); err != nil {
			return
		}
	}

	if r.DPort != 0 || r.SPort != 0 {
		e = expr{}
		e.Type = "payload"
		e.Dreg = 1

		var port int
		if r.SPort != 0 {
			port = r.SPort
			e.Offset = 1
		}
		if r.DPort != 0 {
			port = r.DPort
			e.Offset = 2
		}
		e.Len = 2
		e.Base = "transport"

		nr.Expr = append(nr.Expr, e)

		data := make([]byte, 4)
		binary.BigEndian.PutUint16(data, 0)
		binary.LittleEndian.PutUint16(data[2:4], uint16(port))
		data0 := fmt.Sprintf("0x%x", data)
		if err = (&nr).processCmp(2, data0, "", "", ""); err != nil {
			return
		}
	}

	if r.DAddr != nil {
		if err = (&nr).processAddr(r.DAddr, true); err != nil {
			return
		}
	}

	if r.SAddr != nil {
		if err = (&nr).processAddr(r.SAddr, false); err != nil {
			return
		}
	}

	if r.OIf != nil {
		if err = (&nr).processIf(r.OIf, false); err != nil {
			return
		}
	}

	if r.IIf != nil {
		if err = (&nr).processIf(r.IIf, true); err != nil {
			return
		}
	}

	return
}

func (nr *nftRule) processCmp(length int, data0, data1, data2, data3 string) (err error) {
	e := expr{}
	e.Type = "cmp"
	e.Sreg = 1
	e.Op = "eq"

	e.Data = &data{}
	e.Data.Reg = reg{}
	e.Data.Reg.Len = length
	e.Data.Reg.Type = "value"
	e.Data.Reg.Data0 = data0

	if data1 != "" {
		e.Data.Reg.Data1 = data1
	}
	if data2 != "" {
		e.Data.Reg.Data2 = data2
	}
	if data3 != "" {
		e.Data.Reg.Data3 = data3
	}
	nr.Expr = append(nr.Expr, e)

	return
}

func (nr *nftRule) processIf(iface *net.Interface, isInput bool) (err error) {

	e := expr{}
	e.Type = "meta"
	e.Dreg = 1
	if isInput {
		e.Key = "iif"
	} else {
		e.Key = "oif"
	}

	nr.Expr = append(nr.Expr, e)

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(iface.Index))
	data0 := fmt.Sprintf("0x%x", data)
	if err = (&nr).processCmp(4, data0, "", "", ""); err != nil {
		return
	}

	return

}
func (nr *nftRule) processAddr(ipnet *net.IPNet, isDest bool) (err error) {
	var is4 bool
	//TODO: better way to detect ip4/ip6 ?
	if ipnet.IP.To4() != nil {
		is4 = true
	}

	e := expr{}
	e.Type = "payload"
	e.Dreg = 1

	e.Len = 4
	if isDest {
		e.Offset = 16
		if !is4 {
			e.Offset = 24
			e.Len = 16
		}
	} else {
		e.Offset = 12
		if !is4 {
			e.Offset = 8
			e.Len = 16
		}
	}
	e.Base = "network"

	nr.Expr = append(nr.Expr, e)

	e = expr{}
	e.Type = "bitwise"
	e.Sreg = 1
	e.Dreg = 1
	e.Mask = &mask{}
	if is4 {
		lint := binary.LittleEndian.Uint32(ipnet.Mask)
		e.Mask.Reg = reg{
			Type:  "value",
			Len:   4,
			Data0: fmt.Sprintf("0x%08x", lint),
		}
	} else {
		e.Len = 16
		lint0 := binary.LittleEndian.Uint32(ipnet.Mask[0:4])
		lint1 := binary.LittleEndian.Uint32(ipnet.Mask[4:8])
		lint2 := binary.LittleEndian.Uint32(ipnet.Mask[8:12])
		lint3 := binary.LittleEndian.Uint32(ipnet.Mask[12:16])
		e.Mask.Reg = reg{
			Type:  "value",
			Len:   16,
			Data0: fmt.Sprintf("0x%08x", lint0),
			Data1: fmt.Sprintf("0x%08x", lint1),
			Data2: fmt.Sprintf("0x%08x", lint2),
			Data3: fmt.Sprintf("0x%08x", lint3),
		}
	}

	e.Xor = &xor{}
	if is4 {
		e.Len = 4
		e.Xor.Reg = reg{
			Type:  "value",
			Len:   4,
			Data0: "0x00000000",
		}
	} else {
		e.Len = 16
		e.Xor.Reg = reg{
			Type:  "value",
			Len:   16,
			Data0: "0x00000000",
			Data1: "0x00000000",
			Data2: "0x00000000",
			Data3: "0x00000000",
		}
	}

	nr.Expr = append(nr.Expr, e)

	var data0, data1, data2, data3 string
	length := 4
	if is4 {
		lint0 := binary.LittleEndian.Uint32(ipnet.IP)
		data0 = fmt.Sprintf("0x%08x", lint0)
	} else {
		length = 16
		lint0 := binary.LittleEndian.Uint32(ipnet.IP[0:4])
		data0 = fmt.Sprintf("0x%08x", lint0)
		lint1 := binary.LittleEndian.Uint32(ipnet.IP[4:8])
		data1 = fmt.Sprintf("0x%08x", lint1)
		lint2 := binary.LittleEndian.Uint32(ipnet.IP[8:12])
		data2 = fmt.Sprintf("0x%08x", lint2)
		lint3 := binary.LittleEndian.Uint32(ipnet.IP[12:16])
		data3 = fmt.Sprintf("0x%08x", lint3)
	}
	if err = (&nr).processCmp(length, data0, data1, data2, data3); err != nil {
		return
	}

	return
}

// process 'bitwise' expr
func (r *Rule) processBitwise(nr nftRule, idx int, isDest bool) (err error) {
	if idx+1 >= len(nr.Expr) {
		err = fmt.Errorf("Index out of range %d", idx+1)
		return
	}

	var ip net.IP
	var mask net.IPMask

	if mask, err = reg2IP(nr.Expr[idx].Mask.Reg); err != nil {
		return
	}
	if ip, err = reg2IP(nr.Expr[idx+1].Data.Reg); err != nil {
		return
	}

	if isDest {
		r.DAddr = &net.IPNet{}
		r.DAddr.IP = ip
		r.DAddr.Mask = mask
	} else {
		r.SAddr = &net.IPNet{}
		r.SAddr.IP = ip
		r.SAddr.Mask = mask
	}

	return
}

// Return byte slice suitable for net.IP
func reg2IP(dr reg) (data []byte, err error) {
	length := dr.Len

	switch length {
	// ip4
	case 4:
		if data, err = hex32(dr.Data0); err != nil {
			return
		}
	// ip6
	case 16:
		var tmp []byte
		if tmp, err = hex32(dr.Data0); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex32(dr.Data1); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex32(dr.Data2); err != nil {
			return
		}
		data = append(data, tmp...)
		if tmp, err = hex32(dr.Data3); err != nil {
			return
		}
		data = append(data, tmp...)
	}

	return
}

// convert 32bit hex string encoded in bigendian, to littlendian byte slice
func hex32(hex string) (b []byte, err error) {
	var bigend uint64
	if hex == "" {
		err = fmt.Errorf("hex string empty")
		return
	}
	b = make([]byte, 4)
	bigend, err = strconv.ParseUint(hex, 0, 32)
	if err != nil {
		return
	}

	binary.LittleEndian.PutUint32(b, uint32(bigend))
	return
}

// process 'payload' expr
func (r *Rule) processPayload(nr nftRule, idx int) (err error) {
	/*
		if idx+1 >= len(nr.Expr) {
			err = fmt.Errorf("Index out of range %d", idx+1)
			return
		}
	*/

	switch nr.Expr[idx].Base {
	case "network":

		if nr.Expr[idx+1].Type == "bitwise" {
			// src/dest address
			var isDest bool
			if nr.Expr[idx].Offset == 16 {
				isDest = true
			}
			err = r.processBitwise(nr, idx+1, isDest)
			if err != nil {
				return
			}
		} else {
			// protocol e.g. tcp, udp
			hex := nr.Expr[idx+1].Data.Reg.Data0
			if hex == "" {
				err = fmt.Errorf("Data0 empty")
				return
			}
			var n uint64
			if n, err = strconv.ParseUint(hex, 0, 32); err != nil {
				return
			}
			r.Proto = int(n)
		}
	case "transport":
		// src/dest port
		hex := nr.Expr[idx+1].Data.Reg.Data0
		if hex == "" {
			err = fmt.Errorf("Data0 empty")
			return
		}

		// port number is a 16bit value embedded in a
		// bigendian 32bit register
		var bigend uint64
		if bigend, err = strconv.ParseUint(hex, 0, 32); err != nil {
			return
		}

		length := nr.Expr[idx+1].Data.Reg.Len
		data := make([]byte, length)

		binary.BigEndian.PutUint16(data, uint16(bigend))
		port := binary.LittleEndian.Uint16(data)

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

	hex := nr.Expr[idx+1].Data.Reg.Data0
	if hex == "" {
		err = fmt.Errorf("Data0 empty")
		return
	}
	if iface, err = strconv.ParseUint(hex, 0, 32); err != nil {
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

	seq := time.Now().Unix()

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
		if rule.Expr[i].Data != nil {
			if rule.Expr[i].Data.Reg.Data0 == "0x00000006" { //tcp
				rule.Expr[i].Data.Reg.Data0 = "0x00000011" //udp (hex)
				rule.Handle = 16
			}
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

	jrule := jsonRule{
		Rule: rule,
	}
	var buf []byte
	buf, err = json.Marshal(jrule)

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

func (rule *Rule) AddJson2() (err error) {

	var nrule nftRule
	var cerr error
	var n C.int
	var sn C.ssize_t
	var r *C.struct_nft_rule
	var buf []byte

	if nrule, err = ruleGo2Nft(*rule); err != nil {
		return
	}

	r, cerr = C.nft_rule_alloc()
	if r == nil {
		err = fmt.Errorf("rule alloc failure: %s", cerr)
		return
	}
	defer C.nft_rule_free(r)

	jrule := jsonRule{
		Rule: nrule,
	}
	buf, err = json.Marshal(jrule)

	var parseErr *C.struct_nft_parse_err
	parseErr, cerr = C.nft_parse_err_alloc()
	if parseErr == nil {
		err = fmt.Errorf("rule parse err alloc failure: %s", cerr)
		return
	}
	defer C.nft_parse_err_free(parseErr)

	n, cerr = C.nft_rule_parse(
		r,
		C.enum_nft_parse_type(C.NFT_PARSE_JSON),
		(*C.char)(unsafe.Pointer(&buf[0])),
		parseErr,
	)

	C.nft_rule_attr_unset(r, C.NFT_RULE_ATTR_HANDLE)

	batching := C.nft_batch_is_supported()
	if batching < 0 {
		err = fmt.Errorf("Cannot talk to nfnetlink")
		return
	}

	seq := time.Now().Unix()

	// The following const was not recognised from libmnl.h
	// #define MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
	var bufsize int
	if C.getpagesize() < 8192 {
		bufsize = int(C.getpagesize())
	} else {
		bufsize = 8192
	}
	buf = make([]byte, bufsize)
	batch := C.mnl_nlmsg_batch_start(
		unsafe.Pointer(&buf[0]),
		C.size_t(len(buf)),
	)

	if batching >= 0 {
		seq++
		C.nft_batch_begin(
			(*C.char)(C.mnl_nlmsg_batch_current(batch)),
			C.uint32_t(seq),
		)
		C.mnl_nlmsg_batch_next(batch)
	}

	ruleSeq := seq

	family := C.nft_rule_attr_get_u32(
		r,
		C.NFT_RULE_ATTR_FAMILY,
	)
	seq++
	nlh := C.nft_rule_nlmsg_build_hdr(
		(*C.char)(C.mnl_nlmsg_batch_current(batch)),
		C.NFT_MSG_NEWRULE,
		C.uint16_t(family),
		C.NLM_F_CREATE|C.NLM_F_APPEND|C.NLM_F_ACK,
		C.uint32_t(seq),
	)
	C.nft_rule_nlmsg_build_payload(nlh, r)
	C.mnl_nlmsg_batch_next(batch)

	if batching > 0 {
		seq++
		C.nft_batch_end(
			(*C.char)(C.mnl_nlmsg_batch_current(batch)),
			C.uint32_t(seq),
		)
		C.mnl_nlmsg_batch_next(batch)
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
	sn, cerr = C.mnl_socket_sendto(
		nl,
		unsafe.Pointer(C.mnl_nlmsg_batch_head(batch)),
		C.size_t(C.mnl_nlmsg_batch_size(batch)),
	)
	if sn == -1 {
		err = fmt.Errorf("mnl_socket_sendto: err %s", cerr)
		return
	}
	C.mnl_nlmsg_batch_stop(batch)

	sn, cerr = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if sn == -1 {
		err = fmt.Errorf("mnl_socket_recvfrom: err %s", cerr)
		return
	}

	for sn > 0 {
		n, cerr = C.mnl_cb_run(
			unsafe.Pointer(&buf[0]),
			C.size_t(sn),
			C.uint(ruleSeq),
			portid,
			nil,
			nil,
		)

		if n <= 0 {
			break
		}
		sn = C.mnl_socket_recvfrom(nl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}

	if n == -1 {
		err = fmt.Errorf("mnl_cb_run: err %s", cerr)
		return
	}

	C.mnl_socket_close(nl)

	return
}
