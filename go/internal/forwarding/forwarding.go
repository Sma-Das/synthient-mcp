package forwarding

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const maxForwardedAddresses = 64

func CanonicalClientIP(request *http.Request, trustedProxyHops int, trustedProxyCIDRs []netip.Prefix) (string, error) {
	peer, err := remoteIP(request.RemoteAddr)
	if err != nil {
		return "", err
	}
	if trustedProxyHops == 0 {
		return peer, nil
	}
	if !trustedAddress(peer, trustedProxyCIDRs) {
		return "", fmt.Errorf("direct peer is not in TRUSTED_PROXY_CIDRS")
	}

	chain := make([]string, 0, trustedProxyHops+1)
	for _, forwarded := range request.Header.Values("X-Forwarded-For") {
		for value := range strings.SplitSeq(forwarded, ",") {
			ip, err := canonicalIP(value)
			if err != nil {
				return "", fmt.Errorf("invalid X-Forwarded-For address: %w", err)
			}
			chain = append(chain, ip)
			if len(chain) > maxForwardedAddresses {
				return "", fmt.Errorf("X-Forwarded-For contains too many addresses")
			}
		}
	}
	chain = append(chain, peer)

	index := len(chain) - 1 - trustedProxyHops
	if index < 0 {
		return "", fmt.Errorf("X-Forwarded-For chain is shorter than TRUST_PROXY_HOPS")
	}
	for proxyIndex := index + 1; proxyIndex < len(chain); proxyIndex++ {
		if !trustedAddress(chain[proxyIndex], trustedProxyCIDRs) {
			return "", fmt.Errorf("proxy address %q is not in TRUSTED_PROXY_CIDRS", chain[proxyIndex])
		}
	}
	return chain[index], nil
}

func trustedAddress(value string, prefixes []netip.Prefix) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
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
