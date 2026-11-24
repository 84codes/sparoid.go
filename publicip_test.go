package sparoid

import (
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
)

// stubFetch replaces the HTTP fetch, a URL missing from responses fails like a request error
func stubFetch(t *testing.T, responses map[string]string) *[]string {
	t.Helper()
	var calls []string
	var mu sync.Mutex
	orig := fetchURL
	fetchURL = func(url string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, url)
		if body, ok := responses[url]; ok {
			return body, nil
		}
		return "", errors.New("request failed")
	}
	t.Cleanup(func() { fetchURL = orig })
	return &calls
}

func TestFirstPublicIPv4FallsBackInOrder(t *testing.T) {
	calls := stubFetch(t, map[string]string{"https://api.ipify.org": "198.51.100.4\n"})
	ip := firstPublicIP(ipv4URLs, isPublicIPv4)
	if !ip.Equal(net.ParseIP("198.51.100.4")) {
		t.Errorf("expected 198.51.100.4, got %v", ip)
	}
	if !reflect.DeepEqual(*calls, ipv4URLs) {
		t.Errorf("expected calls %v, got %v", ipv4URLs, *calls)
	}
}

func TestFirstPublicIPv4StopsAtFirstValidAnswer(t *testing.T) {
	calls := stubFetch(t, map[string]string{
		"https://ipv4.icanhazip.com":    "<html>oops</html>",
		"https://checkip.amazonaws.com": "203.0.113.9\n",
		"https://api.ipify.org":         "198.51.100.4",
	})
	ip := firstPublicIP(ipv4URLs, isPublicIPv4)
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("expected 203.0.113.9, got %v", ip)
	}
	want := []string{"https://ipv4.icanhazip.com", "https://checkip.amazonaws.com"}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("expected calls %v, got %v", want, *calls)
	}
}

func TestFirstPublicIPv6FallsBackAndRejectsNonGlobal(t *testing.T) {
	calls := stubFetch(t, map[string]string{
		"https://ipv6.icanhazip.com": "fe80::1",
		"https://api6.ipify.org":     "2606:4700:4700::1111\n",
	})
	ip := firstPublicIP(ipv6URLs, isPublicIPv6)
	if !ip.Equal(net.ParseIP("2606:4700:4700::1111")) {
		t.Errorf("expected 2606:4700:4700::1111, got %v", ip)
	}
	if !reflect.DeepEqual(*calls, ipv6URLs) {
		t.Errorf("expected calls %v, got %v", ipv6URLs, *calls)
	}
}

func TestFirstPublicIPv6RejectsIPv4Answer(t *testing.T) {
	stubFetch(t, map[string]string{"https://ipv6.icanhazip.com": "203.0.113.9"})
	if ip := firstPublicIP(ipv6URLs, isPublicIPv6); ip != nil {
		t.Errorf("expected nil, got %v", ip)
	}
}

func TestResolvePublicIPsDoesNotCacheFailure(t *testing.T) {
	origOS := osPublicIPv6
	osPublicIPv6 = func() net.IP { return nil }
	t.Cleanup(func() { osPublicIPv6 = origOS })
	responses := map[string]string{}
	calls := stubFetch(t, responses)
	c := &Client{key: client.key, hmacKey: client.hmacKey}

	if err := c.resolvePublicIPs(); err == nil {
		t.Fatal("expected an error when every provider fails")
	}
	if len(c.IPs) != 0 {
		t.Fatalf("expected no cached IPs, got %v", c.IPs)
	}
	if len(*calls) != len(ipv4URLs)+len(ipv6URLs) {
		t.Errorf("expected every provider to be tried once, got %v", *calls)
	}

	responses["https://ipv4.icanhazip.com"] = "203.0.113.9"
	if err := c.resolvePublicIPs(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(c.IPs) != 1 || !c.IPs[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("expected [203.0.113.9], got %v", c.IPs)
	}

	n := len(*calls)
	responses["https://ipv4.icanhazip.com"] = "198.51.100.4"
	if err := c.resolvePublicIPs(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(*calls) != n || !c.IPs[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("expected the successful result to be cached, got %v", c.IPs)
	}
}
