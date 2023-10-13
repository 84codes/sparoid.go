package sparoid

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// VERSION is the current version of the client
const VERSION = "0.0.1"

// Client is the main struct for the client
type Client struct {
	key, hmacKey []byte
	IP           net.IP
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
	c.IP, err = c.publicIP()
	if err != nil {
		return
	}
	return
}

// Auth is the main function for the client
func (c *Client) Auth(host string, port int) (err error) {
	c.IP, err = c.publicIP()
	if err != nil {
		return
	}
	return c.send(host, port)
}

func (c *Client) publicIP() (net.IP, error) {
	if c.IP != nil {
		return c.IP, nil
	}
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", "208.67.222.222:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ip, err := resolver.LookupHost(ctx, "myip.opendns.com")
	if err != nil {
		return nil, err
	}

	return net.ParseIP(ip[0]), nil
}

func (c *Client) message() []byte {
	version := uint32(1)
	ts := uint64(time.Now().UTC().UnixNano() / int64(time.Millisecond))
	nounce := make([]byte, 16)
	rand.Read(nounce)
	ipBytes := c.IP.To4()

	buf := make([]byte, 4+8+16+4)
	binary.BigEndian.PutUint32(buf[0:4], version)
	binary.BigEndian.PutUint64(buf[4:12], ts)
	copy(buf[12:28], nounce)
	copy(buf[28:32], ipBytes)

	return buf
}

func (c *Client) encrypt(message []byte) (out []byte, err error) {
	// convert key hexstring to bytes
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}

	message = pad(message)
	out = make([]byte, aes.BlockSize+len(message))
	//iv is the ciphertext up to the blocksize (16)
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
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	encrypted, err := c.encrypt(c.message())
	if err != nil {
		return err
	}
	prefixed := c.prefixHMAC(encrypted)
	conn.Write(prefixed)
	return err
}
