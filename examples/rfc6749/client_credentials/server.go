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
	clientcredentials "github.com/tniah/authkit/rfc6749/client_credentials"
	authkittypes "github.com/tniah/authkit/types"
)

//go:embed index.html static/app.js
var localAssets embed.FS

// SetupServer configures a Client Credentials grant server and returns an
// http.Handler with the following routes:
//
//   - GET /        — playground UI
//   - GET /static/ — static assets (CSS, JS)
//   - POST /token  — token endpoint
func SetupServer(_ *config.Config, lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()
	demoClient := &integsql.Client{
		ClientID:                "cc-demo-client",
		ClientName:              "Client Credentials Demo",
		ClientSecret:            "cc-demo-secret",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"read", "write"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	clientMgr.Register(demoClient)

	// gt is the Client Credentials grant (RFC 6749 §4.4).
	// The client authenticates itself directly at the token endpoint using its
	// own credentials — no resource owner or redirect step is involved.
	// Only confidential clients (those that can securely hold a secret) are
	// permitted; public clients are rejected with invalid_client.
	//
	// SetSupportedClientAuthMethods controls how the client proves its identity:
	//   ClientBasicAuthentication — credentials in the Authorization header (RFC 6749 §2.3.1)
	//   ClientPostAuthentication  — client_id + client_secret as POST body parameters
	gt, err := clientcredentials.Must(
		clientcredentials.NewConfig().
			SetClientManager(clientMgr).
			SetTokenManager(manager.NewTokenManager()).
			SetSupportedClientAuthMethods(map[authkittypes.ClientAuthMethod]bool{
				authkittypes.ClientBasicAuthentication: true,
				authkittypes.ClientPostAuthentication:  true,
			}),
	)
	if err != nil {
		return nil, err
	}

	// RegisterGrant makes the Client Credentials flow available to the server.
	// srv dispatches incoming POST /token requests to gt when
	// grant_type=client_credentials is detected.
	srv := authkit.NewServer()
	srv.RegisterGrant(gt)

	clientJSON, _ := json.Marshal(map[string]interface{}{
		"client_id":                  demoClient.ClientID,
		"client_name":                demoClient.ClientName,
		"client_secret":              demoClient.ClientSecret,
		"token_endpoint_auth_method": demoClient.TokenEndpointAuthMethod,
		"scopes":                     demoClient.Scopes,
	})

	// Pre-render index.html with client config injected as a JS global.
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
