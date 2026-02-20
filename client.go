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
	IPs          []net.IPNet
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
	c.resolvePublicIPs()
	return
}

// Auth is the main function for the client
func (c *Client) Auth(host string, port int) (err error) {
	c.resolvePublicIPs()
	return c.send(host, port)
}

func (c *Client) resolvePublicIPs() {
	if len(c.IPs) > 0 {
		return
	}
	var v4 net.IP
	var v6nets []net.IPNet
	var wg sync.WaitGroup
	wg.Go(func() {
		v4 = fetchPublicIP("https://ipv4.icanhazip.com")
	})
	wg.Go(func() {
		v6nets = globalIPv6FromInterfaces()
		if len(v6nets) == 0 {
			if ip := fetchPublicIP("https://ipv6.icanhazip.com"); ip != nil {
				v6nets = []net.IPNet{{IP: ip, Mask: net.CIDRMask(128, 128)}}
			}
		}
	})
	wg.Wait()
	if v4 != nil {
		c.IPs = append(c.IPs, net.IPNet{IP: v4.To4(), Mask: net.CIDRMask(32, 32)})
	}
	c.IPs = append(c.IPs, v6nets...)
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

func globalIPv6FromInterfaces() []net.IPNet {
	var result []net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil {
				continue
			}
			if ipNet.IP.IsGlobalUnicast() && !ipNet.IP.IsPrivate() {
				result = append(result, *ipNet)
			}
		}
	}
	return result
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
	for _, addr := range addrs {
		serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
		if err != nil {
			return err
		}
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			return err
		}
		if err := c.sendAllPackets(conn); err != nil {
			conn.Close()
			return err
		}
		conn.Close()
	}
	return nil
}

func (c *Client) sendAllPackets(conn *net.UDPConn) error {
	var errs []error
	for _, ipNet := range c.IPs {
		ones, _ := ipNet.Mask.Size()
		if msg, err := MessageV2(ipNet.IP, uint8(ones)); err != nil {
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
