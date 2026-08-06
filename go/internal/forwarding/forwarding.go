package forwarding

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func CanonicalClientIP(request *http.Request, trustedProxyHops int) (string, error) {
	peer, err := remoteIP(request.RemoteAddr)
	if err != nil {
		return "", err
	}
	if trustedProxyHops == 0 {
		return peer, nil
	}

	chain := make([]string, 0, trustedProxyHops+1)
	if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
		for value := range strings.SplitSeq(forwarded, ",") {
			ip, err := canonicalIP(value)
			if err != nil {
				return "", fmt.Errorf("invalid X-Forwarded-For address: %w", err)
			}
			chain = append(chain, ip)
		}
	}
	chain = append(chain, peer)

	index := len(chain) - 1 - trustedProxyHops
	if index < 0 {
		index = 0
	}
	return chain[index], nil
}

func remoteIP(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid remote address: %w", err)
	}
	return canonicalIP(host)
}

func canonicalIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address", value)
	}
	return ip.String(), nil
}
