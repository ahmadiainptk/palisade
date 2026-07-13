// Linux-specific protector implementation.
// On Linux, socket protection is unnecessary — routing tables handle traffic separation.
package protect

import (
	"net"
	"os"
	"strings"
	"syscall"
)

// LinuxProtector is a no-op protector for Linux.
type LinuxProtector struct{}

// Protect is a no-op on Linux. Always returns true.
func (p *LinuxProtector) Protect(socket int32) bool {
	return true
}

// GetResolvers returns system DNS resolvers from /etc/resolv.conf.
func (p *LinuxProtector) GetResolvers() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "8.8.8.8,1.1.1.1"
	}
	var resolvers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := net.ParseIP(parts[1])
				if ip != nil {
					resolvers = append(resolvers, parts[1])
				}
			}
		}
	}
	if len(resolvers) == 0 {
		return "8.8.8.8,1.1.1.1"
	}
	return strings.Join(resolvers, ",")
}

// MakeDialer creates a dialer with no-op protection on Linux.
func MakeLinuxDialer() *net.Dialer {
	return MakeDialer(&LinuxProtector{})
}

// MakeLinuxListenConfig creates a listen config with no-op protection.
func MakeLinuxListenConfig() *net.ListenConfig {
	return MakeListenConfig(&LinuxProtector{})
}

// noopControl does nothing — on Linux we don't need socket protection.
func noopControl(network, address string, c syscall.RawConn) error {
	return nil
}
