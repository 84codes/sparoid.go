package sparoid

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// MessageV2 builds a v2 message (34 or 46 bytes) for the given IP and CIDR prefix.
func MessageV2(ip net.IP, prefixLen uint8) ([]byte, error) {
	ipv4 := ip.To4()
	if ipv4 != nil {
		return messageV2IPv4(ipv4, prefixLen)
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	return messageV2IPv6(ipv6, prefixLen)
}

func messageV2IPv4(ipv4 net.IP, prefixLen uint8) ([]byte, error) {
	buf := make([]byte, 34)
	binary.BigEndian.PutUint32(buf[0:4], 2)
	binary.BigEndian.PutUint64(buf[4:12], uint64(time.Now().UTC().UnixNano()/int64(time.Millisecond)))
	if _, err := rand.Read(buf[12:28]); err != nil {
		return nil, err
	}
	buf[28] = 4
	copy(buf[29:33], ipv4)
	buf[33] = prefixLen
	return buf, nil
}

func messageV2IPv6(ipv6 net.IP, prefixLen uint8) ([]byte, error) {
	buf := make([]byte, 46)
	binary.BigEndian.PutUint32(buf[0:4], 2)
	binary.BigEndian.PutUint64(buf[4:12], uint64(time.Now().UTC().UnixNano()/int64(time.Millisecond)))
	if _, err := rand.Read(buf[12:28]); err != nil {
		return nil, err
	}
	buf[28] = 6
	copy(buf[29:45], ipv6)
	buf[45] = prefixLen
	return buf, nil
}
