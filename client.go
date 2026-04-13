package sparoid

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VERSION is the current version of the client
const VERSION = "0.0.1"

// Client is the main struct for the client
type Client struct {
	key, hmacKey []byte
	IPs          []net.IP
}

// ErrKeyLength is returned when the key is not 32 bytes
var ErrKeyLength = fmt.Errorf("key must be 32 bytes")

// NewClient will return a new client
func NewClient(key, hmacKey string) (c *Client, err error) {
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		err = errors.Join(err, ErrKeyLength)
		return
	}
	decodedHmacKey, err := hex.DecodeString(hmacKey)
	if err != nil {
		err = errors.Join(err, ErrKeyLength)
		return
	}
	c = &Client{
		key:     decodedKey,
		hmacKey: decodedHmacKey,
	}
	if err = c.resolvePublicIPs(); err != nil {
		return
	}
	return
}

// Auth is the main function for the client
func (c *Client) Auth(host string, port int) (err error) {
	if err = c.resolvePublicIPs(); err != nil {
		return
	}
	return c.send(host, port)
}

func (c *Client) resolvePublicIPs() error {
	if len(c.IPs) > 0 {
		return nil
	}
	var v4 net.IP
	var v6 net.IP
	var wg sync.WaitGroup
	wg.Go(func() {
		v4 = fetchPublicIP("https://ipv4.icanhazip.com")
	})
	wg.Go(func() {
		v6 = publicIPv6()
		if v6 == nil {
			v6 = fetchPublicIP("https://ipv6.icanhazip.com")
		}
	})
	wg.Wait()
	if v4 != nil {
		c.IPs = append(c.IPs, v4.To4())
	}
	if v6 != nil {
		c.IPs = append(c.IPs, v6)
	}
	if len(c.IPs) == 0 {
		return fmt.Errorf("failed to resolve any public IP addresses")
	}
	return nil
}

func fetchPublicIP(url string) net.IP {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return net.ParseIP(strings.TrimSpace(string(body)))
}

// publicIPv6 gets the public IPv6 address by asking the OS which source address
// it would use to reach a well-known IPv6 destination (Google DNS).
func publicIPv6() net.IP {
	conn, err := net.DialTimeout("udp6", "[2001:4860:4860::8888]:53", 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr.IP.IsGlobalUnicast() && !addr.IP.IsPrivate() {
		return addr.IP
	}
	return nil
}

func (c *Client) encrypt(message []byte) (out []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}

	message = pad(message)
	out = make([]byte, aes.BlockSize+len(message))
	iv := out[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[aes.BlockSize:], message)
	return
}

func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func (c *Client) prefixHMAC(message []byte) (out []byte) {
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(message)
	out = make([]byte, len(message)+mac.Size())
	copy(out, mac.Sum(nil))
	copy(out[mac.Size():], message)
	return
}

func (c *Client) send(host string, port int) error {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	var errs []error
	for _, addr := range addrs {
		serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := c.sendAllPackets(conn); err != nil {
			errs = append(errs, err)
		}
		conn.Close()
	}
	return errors.Join(errs...)
}

func (c *Client) sendAllPackets(conn *net.UDPConn) error {
	var errs []error
	for _, ip := range c.IPs {
		if msg, err := Message(ip); err != nil {
			errs = append(errs, err)
		} else {
			errs = append(errs, c.sendPacket(conn, msg))
		}
	}
	return errors.Join(errs...)
}

func (c *Client) sendPacket(conn *net.UDPConn, msg []byte) error {
	encrypted, err := c.encrypt(msg)
	if err != nil {
		return err
	}
	prefixed := c.prefixHMAC(encrypted)
	_, err = conn.Write(prefixed)
	return err
}
