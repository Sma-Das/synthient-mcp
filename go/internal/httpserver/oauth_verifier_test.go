package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/Sma-Das/synthient-mcp/go/internal/config"
)

const (
	testIssuer   = "https://id.example.com/"
	testAudience = "https://mcp.example.com/mcp"
)

type signingFixture struct {
	signer jose.Signer
	jwks   []byte
}

func newSigningFixture(t *testing.T) signingFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return signingFixture{signer: signer, jwks: jwks}
}

func (fixture signingFixture) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := jwt.Signed(fixture.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func oauthTestConfig(jwksURL string) config.Config {
	return config.Config{
		AuthMode:       "oauth",
		OAuthIssuerURL: testIssuer,
		OAuthJWKSURL:   jwksURL,
		OAuthAudience:  testAudience,
		MCPResourceURL: testAudience,
	}
}

func TestOIDCVerifierAcceptsSignedES256AccessTokensAndRejectsInvalidOnes(t *testing.T) {
	fixture := newSigningFixture(t)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(fixture.jwks)
	}))
	defer jwksServer.Close()
	verifier := oidcTokenVerifier(oauthTestConfig(jwksServer.URL))

	now := time.Now()
	valid := map[string]any{
		"iss":   testIssuer,
		"aud":   testAudience,
		"sub":   "user-123",
		"scope": "mcp:tools other",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	}
	info, err := verifier(context.Background(), fixture.token(t, valid), nil)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if info.UserID != "user-123" || !slices.Contains(info.Scopes, "mcp:tools") {
		t.Fatalf("token info = %#v", info)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = now.Add(-time.Minute).Unix() }},
		{name: "wrong audience", mutate: func(claims map[string]any) { claims["aud"] = "some-other-client" }},
		{name: "wrong issuer", mutate: func(claims map[string]any) { claims["iss"] = "https://evil.example/" }},
		{name: "missing subject", mutate: func(claims map[string]any) { delete(claims, "sub") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{}
			for key, value := range valid {
				claims[key] = value
			}
			test.mutate(claims)
			if _, err := verifier(context.Background(), fixture.token(t, claims), nil); !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("error = %v; want ErrInvalidToken", err)
			}
		})
	}

	other := newSigningFixture(t)
	if _, err := verifier(context.Background(), other.token(t, valid), nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("token signed by an unknown key: error = %v", err)
	}
}

func TestOIDCVerifierDoesNotHangOnAStalledJWKSEndpoint(t *testing.T) {
	previous := tokenVerifyTimeout
	tokenVerifyTimeout = 200 * time.Millisecond
	defer func() { tokenVerifyTimeout = previous }()

	release := make(chan struct{})
	jwksServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-release:
		case <-request.Context().Done():
		}
	}))
	defer jwksServer.Close()
	defer close(release)

	fixture := newSigningFixture(t)
	verifier := oidcTokenVerifier(oauthTestConfig(jwksServer.URL))
	token := fixture.token(t, map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user", "exp": time.Now().Add(time.Hour).Unix()})

	started := time.Now()
	_, err := verifier(context.Background(), token, nil)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("verification took %s with a stalled JWKS endpoint", elapsed)
	}
}

func TestOIDCVerifierRejectsOversizedJWKS(t *testing.T) {
	previous := maxJWKSResponseBytes
	maxJWKSResponseBytes = 64
	defer func() { maxJWKSResponseBytes = previous }()

	fixture := newSigningFixture(t)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(fixture.jwks)
		_, _ = response.Write([]byte(strings.Repeat(" ", 128)))
	}))
	defer jwksServer.Close()

	verifier := oidcTokenVerifier(oauthTestConfig(jwksServer.URL))
	token := fixture.token(t, map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := verifier(context.Background(), token, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("error = %v", err)
	}
}

func TestOIDCVerifierJWKSSizeCapIsExact(t *testing.T) {
	fixture := newSigningFixture(t)
	previous := maxJWKSResponseBytes
	defer func() { maxJWKSResponseBytes = previous }()
	token := fixture.token(t, map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user", "exp": time.Now().Add(time.Hour).Unix()})

	for _, test := range []struct {
		name    string
		padding int
		valid   bool
	}{
		{name: "exactly at the cap", padding: 0, valid: true},
		{name: "one byte over the cap", padding: 1, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			maxJWKSResponseBytes = int64(len(fixture.jwks))
			jwksServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write(fixture.jwks)
				_, _ = response.Write([]byte(strings.Repeat(" ", test.padding)))
			}))
			defer jwksServer.Close()
			_, err := oidcTokenVerifier(oauthTestConfig(jwksServer.URL))(context.Background(), token, nil)
			if (err == nil) != test.valid {
				t.Fatalf("error = %v; want valid=%t", err, test.valid)
			}
		})
	}
}
