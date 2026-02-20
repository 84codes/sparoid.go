package sparoid

import (
	"errors"
	"net"
	"testing"
)

var (
	key       = "0000000000000000000000000000000000000000000000000000000000000000"
	hmacKey   = "0000000000000000000000000000000000000000000000000000000000000000"
	client, _ = NewClient(key, hmacKey)
)

func ipNet(cidr string) net.IPNet {
	ip, n, _ := net.ParseCIDR(cidr)
	n.IP = ip // preserve the host IP, not the masked network address
	return *n
}

func TestClientCreatesNewClient(t *testing.T) {
	client, err := NewClient(key, hmacKey)
	if err != nil {
		t.Errorf("Expected no error %s", err)
	}
	if client == nil {
		t.Errorf("Expected client to be created")
	}
}

func TestClientGuardsAgainstShortKeys(t *testing.T) {
	_, err1 := NewClient("short", hmacKey)
	_, err2 := NewClient(key, "short")
	if errors.Is(err1, ErrKeyLength) == false && errors.Is(err2, ErrKeyLength) == false {
		t.Errorf("Expected ErrKeyLength")
	}
}

func TestClientEncryptsMessages(t *testing.T) {
	c := &Client{key: client.key, hmacKey: client.hmacKey, IPs: []net.IPNet{ipNet("127.0.0.1/32")}}
	msg, err := MessageV2(net.ParseIP("127.0.0.1"), 32)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	encrypted, err := c.encrypt(msg)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// 34 bytes padded to 48 + 16 IV = 64
	if len(encrypted) != 64 {
		t.Errorf("Expected encrypted message length to be 64, got %d", len(encrypted))
	}
}

func TestClientAddsHMAC(t *testing.T) {
	c := &Client{key: client.key, hmacKey: client.hmacKey, IPs: []net.IPNet{ipNet("127.0.0.1/32")}}
	msg, _ := MessageV2(net.ParseIP("127.0.0.1"), 32)
	encrypted, _ := c.encrypt(msg)
	prefixed := c.prefixHMAC(encrypted)
	// 64 encrypted + 32 HMAC = 96
	if len(prefixed) != 96 {
		t.Errorf("Expected prefixed message length to be 96, got %d", len(prefixed))
	}
}

func TestClientSendsIPv4Packet(t *testing.T) {
	server, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port

	c := &Client{key: client.key, hmacKey: client.hmacKey, IPs: []net.IPNet{ipNet("127.0.0.1/32")}}
	go func() {
		err := c.Auth("127.0.0.1", port)
		if err != nil {
			t.Errorf("Expected no error %s", err)
		}
	}()

	buf := make([]byte, 512)
	// v2 IPv4 (34 bytes -> pad to 48 -> +16 IV = 64 encrypted -> +32 HMAC = 96)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Expected no error %s", err)
	}
	if n != 96 {
		t.Errorf("Expected packet length to be 96, got %d", n)
	}
}

func TestClientSendsIPv6Packet(t *testing.T) {
	server, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port

	c := &Client{key: client.key, hmacKey: client.hmacKey, IPs: []net.IPNet{ipNet("2001:db8::1/64")}}
	go func() {
		err := c.send("127.0.0.1", port)
		if err != nil {
			t.Errorf("Expected no error %s", err)
		}
	}()

	buf := make([]byte, 512)

	// v2 IPv6 (46 bytes -> pad to 48 -> +16 IV = 64 encrypted -> +32 HMAC = 96)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("Expected no error %s", err)
	}
	if n != 96 {
		t.Errorf("Expected v2 IPv6 packet length to be 96, got %d", n)
	}
}

func TestClientSendsBothIPv4AndIPv6(t *testing.T) {
	server, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port

	c := &Client{
		key: client.key, hmacKey: client.hmacKey,
		IPs: []net.IPNet{ipNet("127.0.0.1/32"), ipNet("2001:db8::1/64")},
	}
	go func() {
		err := c.send("127.0.0.1", port)
		if err != nil {
			t.Errorf("Expected no error %s", err)
		}
	}()

	buf := make([]byte, 512)
	// Expect 2 packets: v2 IPv4 + v2 IPv6 (IPv4 first)
	for i := 0; i < 2; i++ {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("packet %d: unexpected error: %s", i, err)
		}
		if n != 96 {
			t.Errorf("packet %d: expected length 96, got %d", i, n)
		}
	}
}

func TestPad(t *testing.T) {
	message := []byte("hello")
	padded := pad(message)
	if len(padded) != 16 {
		t.Errorf("Expected padded message length to be 16, got %d", len(padded))
	}
}

func TestCanConnectToSparoidServer(t *testing.T) {
	clusterName := "localhost"
	err := client.Auth(clusterName, 8484)
	if err != nil {
		t.Fatal("Failed to dial: ", err)
	}
}
