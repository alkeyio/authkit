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
	"github.com/tniah/authkit/rfc6749/ropc"
	"github.com/tniah/authkit/rfc7662"
	authkittypes "github.com/tniah/authkit/types"
)

//go:embed index.html static/app.js
var localAssets embed.FS

// SetupServer configures a Resource Owner Password Credentials grant server
// with a Token Introspection endpoint (RFC 7662) and returns an http.Handler
// with the following routes:
//
//   - GET /          — playground UI
//   - GET /static/   — static assets (CSS, JS)
//   - POST /token    — token endpoint
//   - POST /introspect — introspection endpoint
func SetupServer(_ *config.Config, lg *slog.Logger) (http.Handler, error) {
	clientMgr := manager.NewClientManager()
	demoClient := &integsql.Client{
		ClientID:                "introspect-demo-client",
		ClientName:              "Token Introspection Demo",
		ClientSecret:            "introspect-demo-secret",
		GrantTypes:              []string{"password"},
		Scopes:                  []string{"profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	clientMgr.Register(demoClient)

	userMgr := manager.NewUserManager()
	demoUser := &manager.User{
		UserID:   "a1ce0000-0000-4000-8000-000000000001",
		Username: "alice",
		Password: "secret",
	}
	userMgr.Register(demoUser)

	// tokenMgr is shared between the ROPC grant and the introspection endpoint
	// so that tokens issued at /token are visible to /introspect.
	tokenMgr := manager.NewTokenManager()

	gt, err := ropc.Must(
		ropc.NewConfig().
			SetClientManager(clientMgr).
			SetUserManager(userMgr).
			SetTokenManager(tokenMgr).
			SetSupportedClientAuthMethods(map[authkittypes.ClientAuthMethod]bool{
				authkittypes.ClientBasicAuthentication: true,
				authkittypes.ClientPostAuthentication:  true,
			}),
	)
	if err != nil {
		return nil, err
	}

	// Configure the token introspection endpoint (RFC 7662).
	//
	// clientMgr handles two responsibilities here:
	//   - Authenticate: verifies the caller's credentials before processing the
	//     request (the caller acts as a resource server, not the token owner).
	//   - CheckPermission: decides whether the authenticated client may inspect
	//     a given token. The demo manager allows all clients unconditionally.
	//
	// tokenMgr.QueryByToken looks up the token from the in-memory store.
	// tokenMgr.Inspect builds the claim set returned in the JSON response
	// (scope, client_id, token_type, iat, exp, sub, jti).
	//
	// The default endpoint name is rfc7662.EndpointNameTokenIntrospection
	// ("introspection"), which is used by srv.EndpointResponse to route the
	// request to this flow.
	introspect, err := rfc7662.MustTokenIntrospectionFlow(
		rfc7662.NewConfig().
			SetClientManager(clientMgr).
			SetTokenManager(tokenMgr).
			SetEndpointName(rfc7662.EndpointNameTokenIntrospection),
	)
	if err != nil {
		return nil, err
	}

	srv := authkit.NewServer()
	srv.RegisterGrant(gt)
	// RegisterEndpoint makes the introspection flow available under its
	// configured endpoint name. srv.EndpointResponse dispatches to it by name.
	srv.RegisterEndpoint(introspect)

	clientJSON, _ := json.Marshal(map[string]interface{}{
		"client_id":                  demoClient.ClientID,
		"client_name":                demoClient.ClientName,
		"client_secret":              demoClient.ClientSecret,
		"token_endpoint_auth_method": demoClient.TokenEndpointAuthMethod,
		"scopes":                     demoClient.Scopes,
	})

	userJSON, _ := json.Marshal(map[string]interface{}{
		"username": demoUser.Username,
		"password": demoUser.Password,
	})

	// Pre-render index.html with client and user config injected as JS globals.
	rawHTML, _ := localAssets.ReadFile("index.html")
	injected := strings.Replace(
		string(rawHTML),
		"</head>",
		fmt.Sprintf("<script>window.__CLIENT__ = %s; window.__USER__ = %s;</script>\n</head>", clientJSON, userJSON),
		1,
	)

	mux := http.NewServeMux()

	// GET / — serve the playground UI with config pre-injected.
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

	// POST /introspect — token introspection endpoint (RFC 7662).
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.EndpointResponse(r, w, rfc7662.EndpointNameTokenIntrospection); err != nil {
			lg.Error("introspect request failed", "error", err)
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
