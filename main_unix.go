//go:build unix

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setSockopt(fd uintptr) error {
	// It's unfortunate that we need `unix` here; SO_REUSEPORT is defined on linuxarm64 but not linux...
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
