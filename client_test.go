package sparoid

import (
	//"bytes"
	"net"
	"testing"

	//"golang.org/x/crypto/ssh"
	"errors"
	"regexp"
)

var (
	key       = "0000000000000000000000000000000000000000000000000000000000000000"
	hmacKey   = "0000000000000000000000000000000000000000000000000000000000000000"
	client, _ = NewClient(key, hmacKey)
)

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

func TestClientResolvesPublicIP(t *testing.T) {
	ip, err := client.publicIP()
	if err != nil {
		t.Errorf("Expected no error %s", err)
	}
	match, err := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, ip.String())
	if err != nil {
		t.Errorf("Expected no error %s", err)
	}
	if !match {
		t.Errorf("Expected IP address to match pattern")
	}
}

func TestClientCreatesAMessage(t *testing.T) {
	message := client.message()
	if len(message) != 32 {
		t.Errorf("Expected message length to be 32, got %d", len(message))
	}
}

func TestClientEncryptsMessages(t *testing.T) {
	message := client.message()
	encrypted, err := client.encrypt(message)
	if err != nil {
		t.Errorf("Expected no error %s", err)
		t.FailNow()
	}
	t.Logf("Encrypted message: %x", encrypted)
	if len(encrypted) != 64 {
		t.Errorf("Expected encrypted message length to be 64, got %d", len(encrypted))
	}
}

func TestClientAddsHMAC(t *testing.T) {
	message := client.message()
	encrypted, _ := client.encrypt(message)
	prefixed := client.prefixHMAC(encrypted)
	if len(prefixed) != 96 {
		t.Errorf("Expected prefixed message length to be 96, got %d", len(prefixed))
	}
}

func TestClientSendsMessage(t *testing.T) {
	server, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port
	go func() {
		err := client.Auth("127.0.0.1", port)
		if err != nil {
			t.Errorf("Expected no error %s", err)
		}
	}()
	buf := make([]byte, 512)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Errorf("Expected no error %s", err)
	}
	if n != 96 {
		t.Errorf("Expected received message length to be 96 got %d", n)
	}
}

func TestClientOpensPortForPassedInIPArgument(t *testing.T) {
	ip := "127.0.0.1"
	server, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port
	go func() {
		err := client.Auth(ip, port)
		if err != nil {
			t.Errorf("Expected no error %s", err)
		}
	}()
	buf := make([]byte, 512)
	n, _, _ := server.ReadFrom(buf)
	if n != 96 {
		t.Errorf("Expected received message length to be 96, got %d", n)
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
