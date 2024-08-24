//go:build windows

package main

import "errors"

func setSockopt(fd uintptr) error {
	return errors.New("unsupported")
}
