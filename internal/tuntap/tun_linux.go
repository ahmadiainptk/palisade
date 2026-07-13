// Package tuntap provides Linux TUN device creation.
// The original MakeTunDeviceFromFD is in tun.go; this file adds Linux TUN creation.
package tuntap

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevice   = "/dev/net/tun"
	iffTun      = 0x0001
	iffNoPi     = 0x1000
	tunSetIff   = 0x400454ca
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [16 - 2]byte
}

// CreateTUN creates a new TUN device and returns the associated *os.File.
// On success, the TUN interface will be named as specified by 'name' (e.g. "tun0").
// Returns the *os.File for reading/writing IP packets, and the actual interface name.
func CreateTUN(name string) (*os.File, string, error) {
	if len(name) >= 16 {
		return nil, "", fmt.Errorf("interface name too long: %s", name)
	}

	fd, err := syscall.Open(tunDevice, syscall.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open %s: %w", tunDevice, err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPi

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, "", fmt.Errorf("ioctl TUNSETIFF failed: %w", errno)
	}

	// Find the actual name (null-terminated)
	actualName := ""
	for i := 0; i < len(req.Name); i++ {
		if req.Name[i] == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}
	if actualName == "" {
		syscall.Close(fd)
		return nil, "", errors.New("failed to determine TUN interface name")
	}

	file := os.NewFile(uintptr(fd), tunDevice)
	if file == nil {
		syscall.Close(fd)
		return nil, "", errors.New("failed to wrap TUN file descriptor")
	}

	return file, actualName, nil
}
