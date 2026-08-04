package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tniah/authkit"
	"github.com/tniah/authkit/examples/assets"
	"github.com/tniah/authkit/examples/config"
	"github.com/tniah/authkit/examples/manager"
	"github.com/tniah/authkit/examples/middleware"
	integsql "github.com/tniah/authkit/integrations/sql"
	authcodegrant "github.com/tniah/authkit/rfc6749/authorization_code"
	"github.com/tniah/authkit/rfc7636"
)

//go:embed index.html static/app.js
var localAssets embed.FS

// SetupServer configures an Authorization Code grant server with PKCE (RFC 7636)
// and returns an http.Handler with the following routes:
//
//   - GET /           — playground UI
//   - GET /static/    — static assets (CSS, JS)
//   - GET /authorize  — authorization endpoint
//   - POST /token     — token endpoint
func SetupServer(cfg *config.Config, lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()
	publicClient := &integsql.Client{
		ClientID:                "pkce-demo-client",
		ClientName:              "PKCE Demo",
		RedirectURIs:            []string{fmt.Sprintf("http://%s:%s/callback", publicHost(cfg.Address), cfg.Port)},
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"profile", "email"},
		TokenEndpointAuthMethod: "none",
	}
	clientMgr.Register(publicClient)

	userMgr := manager.NewUserManager()
	alice := &manager.User{
		UserID:   "a1ce0000-0000-4000-8000-000000000001",
		Username: "alice",
		Password: "secret",
	}
	userMgr.Register(alice)

	// pkce is the PKCE extension (RFC 7636). It plugs into the Authorization
	// Code grant via RegisterExtension and handles two responsibilities:
	//
	//   - ValidateAuthorizationRequest: checks that code_challenge is present
	//     and well-formed. For public clients (none auth method), PKCE is
	//     required by default — the request is rejected if code_challenge is
	//     missing.
	//   - ProcessAuthorizationCode: stores code_challenge and
	//     code_challenge_method on the authorization code before it is persisted.
	//   - ValidateTokenRequest: verifies the code_verifier submitted at the
	//     token endpoint against the stored code_challenge. For S256, the
	//     verifier is hashed (BASE64URL(SHA256(verifier))) before comparison.
	//
	// NewOptions defaults: required=true, allowPlain=true. SetAllowPlain(false)
	// enforces S256-only per RFC 9700 §2.1.
	pkce := rfc7636.New(
		rfc7636.NewOptions().
			SetRequired(true).
			SetAllowPlain(true),
	)

	// gt is the Authorization Code grant (RFC 6749 §4.1) with PKCE registered
	// as an extension. RegisterExtension inspects pkce and adds it to the
	// authorization-request, auth-code, and token-request extension chains.
	gt, err := authcodegrant.Must(
		authcodegrant.NewConfig().
			SetClientManager(clientMgr).
			SetUserManager(userMgr).
			SetAuthCodeManager(manager.NewAuthorizationCodeManager()).
			SetTokenManager(manager.NewTokenManager()).
			RegisterExtension(pkce),
	)
	if err != nil {
		return nil, err
	}

	// RegisterGrant makes the Authorization Code + PKCE flow available to the
	// server. srv dispatches GET /authorize when response_type=code is detected,
	// and POST /token when grant_type=authorization_code is detected.
	srv := authkit.NewServer()
	srv.RegisterGrant(gt)

	clientJSON, _ := json.Marshal(map[string]interface{}{
		"client_id":                  publicClient.ClientID,
		"client_name":                publicClient.ClientName,
		"redirect_uris":              publicClient.RedirectURIs,
		"response_types":             publicClient.ResponseTypes,
		"token_endpoint_auth_method": publicClient.TokenEndpointAuthMethod,
		"scopes":                     publicClient.Scopes,
	})

	// Pre-render index.html with the client config injected as a JS global.
	rawHTML, _ := localAssets.ReadFile("index.html")
	injected := strings.Replace(
		string(rawHTML),
		"</head>",
		fmt.Sprintf("<script>window.__CLIENT__ = %s;</script>\n</head>", clientJSON),
		1,
	)

	mux := http.NewServeMux()

	// GET / — serve the playground UI with client config pre-injected.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(injected))
	})

	// GET /static/app.js — serve app-specific JS.
	appFS, _ := fs.Sub(localAssets, "static")
	mux.Handle("GET /static/app.js", http.StripPrefix("/static/", http.FileServer(http.FS(appFS))))

	// GET /static/ — serve shared assets (style.css, fonts.css, fonts/).
	sharedFS, _ := fs.Sub(assets.FS, "files")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sharedFS))))

	// GET /authorize — authorization endpoint.
	// In a real application, retrieve the authenticated user from the session.
	// For this example, alice is used to simulate a logged-in session.
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.CreateAuthorizationResponse(r, w, alice); err != nil {
			lg.Error("authorization request failed", "error", err, "client_id", r.URL.Query().Get("client_id"))
		}
	})

	// POST /token — token endpoint.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.CreateTokenResponse(r, w); err != nil {
			lg.Error("token request failed", "error", err)
		}
	})

	return middleware.AccessLog(lg)(mux), nil
}

// publicHost resolves the host used in public-facing URLs (redirect URIs, logs).
// 0.0.0.0 is a valid bind address but not a routable host, so it is mapped to localhost.
func publicHost(addr string) string {
	if addr == "0.0.0.0" {
		return "localhost"
	}
	return addr
}
