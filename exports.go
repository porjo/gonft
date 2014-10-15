package nftnl

import (
	//	"reflect"
	"fmt"
	"unsafe"
)

/*
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
*/
import "C"

//export go_callback
func go_callback(nlh *C.struct_nlmsghdr, outputType unsafe.Pointer) int {
	fmt.Printf("callback enter\n")

	buf := make([]byte, 4096)

	t := NewTable()
	defer t.Close()
	if t == nil {
		return C.MNL_CB_OK
	}

	if C.nft_table_nlmsg_parse(nlh, t.table) < 0 {
		return C.MNL_CB_OK
	}

	//fmt.Printf("buf %v", buf)

	C.nft_table_snprintf(
		(*C.char)(unsafe.Pointer(&buf[0])),
		(C.size_t)(len(buf)),
		t.table,
		*(*C.uint32_t)(outputType),
		0)
	fmt.Printf("callback buf %s\n", buf)

	return C.MNL_CB_OK
}

/*
//export go_callback
func go_callback(p1 *C.uchar, p2 C.uint32_t, p3 unsafe.Pointer) {
	// c buffer to go slice without copying
	var buf []byte
	length := int(p2)
	b := (*reflect.SliceHeader)((unsafe.Pointer(&buf)))
	b.Cap = length
	b.Len = length
	b.Data = uintptr(unsafe.Pointer(p1))
	clientCb(buf, (*UserCtx)(p3))
}
*/
