package sparoid

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestMessageIPv4(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	msg, err := Message(ip)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(msg) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(msg))
	}
	version := binary.BigEndian.Uint32(msg[0:4])
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}
	if !net.IP(msg[28:32]).Equal(ip.To4()) {
		t.Errorf("expected IP %s at offset 28, got %s", ip, net.IP(msg[28:32]))
	}
}

func TestMessageIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	msg, err := Message(ip)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(msg) != 44 {
		t.Fatalf("expected 44 bytes, got %d", len(msg))
	}
	version := binary.BigEndian.Uint32(msg[0:4])
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}
	if !net.IP(msg[28:44]).Equal(ip) {
		t.Errorf("expected IP %s at offset 28, got %s", ip, net.IP(msg[28:44]))
	}
}
