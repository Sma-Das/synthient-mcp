package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
)

// Bounds for the identity provider's JWKS endpoint. A stalled or oversized
// key-set response must not pin MCP request slots, so fetches have their own
// deadline and size cap, and each verification has an overall deadline.
var (
	jwksFetchTimeout     = 10 * time.Second
	tokenVerifyTimeout   = 5 * time.Second
	maxJWKSResponseBytes = int64(1 << 20)
)

// supportedSigningAlgs lists the asymmetric JOSE algorithms accepted for
// access tokens. Without an explicit list, go-oidc accepts only RS256.
var supportedSigningAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
	oidc.EdDSA,
}

func oidcTokenVerifier(cfg config.Config) auth.TokenVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = jwksFetchTimeout
	transport.MaxResponseHeaderBytes = 64 << 10
	jwksClient := &http.Client{
		Timeout:   jwksFetchTimeout,
		Transport: limitedBodyTransport{base: transport, limit: maxJWKSResponseBytes},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	keySet := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), jwksClient), cfg.OAuthJWKSURL)
	return newTokenVerifier(cfg, keySet)
}

func newTokenVerifier(cfg config.Config, keySet oidc.KeySet) auth.TokenVerifier {
	verifier := oidc.NewVerifier(cfg.OAuthIssuerURL, keySet, &oidc.Config{
		ClientID:             cfg.OAuthAudience,
		SupportedSigningAlgs: supportedSigningAlgs,
	})
	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		ctx, cancel := context.WithTimeout(ctx, tokenVerifyTimeout)
		defer cancel()
		token, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			return nil, fmt.Errorf("%w: bearer token verification failed", auth.ErrInvalidToken)
		}
		claims := map[string]json.RawMessage{}
		if err := token.Claims(&claims); err != nil {
			return nil, fmt.Errorf("%w: bearer token claims are invalid", auth.ErrInvalidToken)
		}
		subject := stringClaim(claims["sub"])
		if subject == "" || len(subject) > 512 {
			return nil, fmt.Errorf("%w: bearer token subject is missing or invalid", auth.ErrInvalidToken)
		}
		scopes := append(scopeClaim(claims["scope"]), scopeClaim(claims["scp"])...)
		return &auth.TokenInfo{
			Scopes:     uniqueStrings(scopes),
			Expiration: token.Expiry,
			UserID:     subject,
			Extra:      map[string]any{"issuer": token.Issuer},
		}, nil
	}
}

// limitedBodyTransport fails responses whose bodies exceed limit bytes.
type limitedBodyTransport struct {
	base  http.RoundTripper
	limit int64
}

func (transport limitedBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = &limitedBody{ReadCloser: response.Body, remaining: transport.limit}
	return response, nil
}

type limitedBody struct {
	io.ReadCloser
	remaining int64
}

var errJWKSTooLarge = errors.New("JWKS response exceeds the size limit")

func (body *limitedBody) Read(buffer []byte) (int, error) {
	if body.remaining <= 0 {
		// Distinguish an exact-size body from an oversized one.
		var probe [1]byte
		if n, _ := body.ReadCloser.Read(probe[:]); n > 0 {
			return 0, errJWKSTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	n, err := body.ReadCloser.Read(buffer)
	body.remaining -= int64(n)
	return n, err
}

func oauthProtection(cfg config.Config, verifier auth.TokenVerifier) func(http.Handler) http.Handler {
	return auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL(cfg.MCPResourceURL),
		Scopes:              cfg.OAuthRequiredScopes,
	})
}

func protectedResourceHandler(cfg config.Config) http.Handler {
	return auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               cfg.MCPResourceURL,
		AuthorizationServers:   []string{cfg.OAuthIssuerURL},
		ScopesSupported:        cfg.OAuthRequiredScopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Synthient Intelligence MCP",
	})
}

func resourceMetadataURL(resource string) string {
	parsed, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	path := "/.well-known/oauth-protected-resource"
	if resourcePath := strings.TrimSuffix(parsed.Path, "/"); resourcePath != "" {
		path += resourcePath
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: path}).String()
}

func resourceMetadataPath(resource string) string {
	parsed, err := url.Parse(resourceMetadataURL(resource))
	if err != nil || parsed.Path == "" {
		return "/.well-known/oauth-protected-resource"
	}
	return parsed.Path
}

func stringClaim(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return strings.TrimSpace(value)
}

func scopeClaim(raw json.RawMessage) []string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.Fields(text)
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return values
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				result = append(result, value)
			}
		}
	}
	return result
}
