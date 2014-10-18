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
//	"fmt"
)

/*
#cgo linux LDFLAGS: -lnftnl -lmnl

#include <netinet/in.h>

#include <linux/netfilter.h>
*/
import "C"

var familyMap map[string]int
var protoMap map[string]int

func init() {
	familyMap = make(map[string]int)
	familyMap["ip"] = C.NFPROTO_UNSPEC
	familyMap["ip4"] = C.NFPROTO_IPV4
	familyMap["ip6"] = C.NFPROTO_IPV6

	protoMap = make(map[string]int)
	protoMap["tcp"] = C.IPPROTO_TCP
	protoMap["udp"] = C.IPPROTO_UDP
}
