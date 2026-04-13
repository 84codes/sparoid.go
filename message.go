package sparoid

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Message builds a v1 message for the given IP.
// Format: version(4) + timestamp(8) + nonce(16) + ip(4 or 16)
// IPv4: 32 bytes, IPv6: 44 bytes. Server distinguishes by length.
func Message(ip net.IP) ([]byte, error) {
	if ipv4 := ip.To4(); ipv4 != nil {
		return message(ipv4, 32)
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		return message(ipv6, 44)
	}
	return nil, fmt.Errorf("invalid IP address")
}

func message(ip net.IP, size int) ([]byte, error) {
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], 1)
	binary.BigEndian.PutUint64(buf[4:12], uint64(time.Now().UTC().UnixNano()/int64(time.Millisecond)))
	if _, err := rand.Read(buf[12:28]); err != nil {
		return nil, err
	}
	copy(buf[28:], ip)
	return buf, nil
}
