//go:build linux || android

package dialer

import (
	"reflect"
	"syscall"
)

// discoverSyscallConn finds the raw socket behind a connection that does not
// implement syscall.Conn itself.
//
// The connections reaching the UDP wrappers are sing's own types, which are
// rarely net.Conn, but most of them embed a syscall.Conn one or two fields
// deep (a *net.UDPConn behind a reader, or a raw *net.UDPConn). Only exported
// or package-level fields are inspected, and the search is bounded, so a
// connection without a raw socket simply reports none.
func discoverSyscallConn(conn any) syscall.Conn {
	return discoverSyscallConnDepth(conn, 0)
}

const discoverSyscallConnMaxDepth = 3

func discoverSyscallConnDepth(conn any, depth int) syscall.Conn {
	if conn == nil || depth > discoverSyscallConnMaxDepth {
		return nil
	}
	value := reflect.ValueOf(conn)
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}
	var candidates []reflect.Value
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.CanInterface() {
			continue
		}
		if syscallConn, isSyscallConn := field.Interface().(syscall.Conn); isSyscallConn {
			return syscallConn
		}
		candidates = append(candidates, field)
	}
	value = reflect.Value{}
	for _, candidate := range candidates {
		candidateType := candidate.Type()
		if candidateType.Kind() != reflect.Struct && candidateType.Kind() != reflect.Pointer {
			continue
		}
		if candidateType.Kind() == reflect.Pointer && candidate.IsNil() {
			continue
		}
		if syscallConn := discoverSyscallConnDepth(candidate.Interface(), depth+1); syscallConn != nil {
			return syscallConn
		}
	}
	return nil
}
