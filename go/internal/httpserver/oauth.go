package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
)

func oidcTokenVerifier(cfg config.Config) auth.TokenVerifier {
	keySet := oidc.NewRemoteKeySet(context.Background(), cfg.OAuthJWKSURL)
	verifier := oidc.NewVerifier(cfg.OAuthIssuerURL, keySet, &oidc.Config{ClientID: cfg.OAuthAudience})
	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
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
