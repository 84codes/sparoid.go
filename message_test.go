package sparoid

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestMessageV2IPv4(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	msg, err := MessageV2(ip, 32)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(msg) != 34 {
		t.Fatalf("expected 34 bytes, got %d", len(msg))
	}
	version := binary.BigEndian.Uint32(msg[0:4])
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
	if msg[28] != 4 {
		t.Errorf("expected family 4, got %d", msg[28])
	}
	if !net.IP(msg[29:33]).Equal(ip.To4()) {
		t.Errorf("expected IP %s at offset 29, got %s", ip, net.IP(msg[29:33]))
	}
	if msg[33] != 32 {
		t.Errorf("expected range 32, got %d", msg[33])
	}
}

func TestMessageV2IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	msg, err := MessageV2(ip, 128)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(msg) != 46 {
		t.Fatalf("expected 46 bytes, got %d", len(msg))
	}
	version := binary.BigEndian.Uint32(msg[0:4])
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
	if msg[28] != 6 {
		t.Errorf("expected family 6, got %d", msg[28])
	}
	if !net.IP(msg[29:45]).Equal(ip) {
		t.Errorf("expected IP %s at offset 29, got %s", ip, net.IP(msg[29:45]))
	}
	if msg[45] != 128 {
		t.Errorf("expected range 128, got %d", msg[45])
	}
}
