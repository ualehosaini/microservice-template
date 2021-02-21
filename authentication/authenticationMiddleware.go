package Authentication

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Define our struct
type AuthenticationMiddleware struct {
	tokenUsers map[string]string
}

// Initialize it somewhere
func (amw *AuthenticationMiddleware) Populate() {
	amw.tokenUsers["00000000"] = "user0"
	amw.tokenUsers["aaaaaaaa"] = "userA"
	amw.tokenUsers["05f717e5"] = "randomUser"
	amw.tokenUsers["deadbeef"] = "user0"
}

func AuthConfig() (oauth2Config oauth2.Config, state string, verifier *oidc.IDTokenVerifier, ctx context.Context) {
	//Authentication setup
	configURL := "http://localhost:8080/auth/realms/ubivius"
	ctx = context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		log.Println("Auth panic")
		panic(err)
	}

	clientID := "ubivius-client"
	clientSecret := "ef14f638-98ad-4c5b-9320-a223077e0797"

	redirectURL := "http://localhost:9090/ubivius/callback"
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	state = "somestate"

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier = provider.Verifier(oidcConfig)
	return oauth2Config, state, verifier, ctx
}

// Middleware function, which will be called for each request
func (amw *AuthenticationMiddleware) NamePlaceholder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth2Config, state, verifier, ctx := AuthConfig()
		rawAccessToken := r.Header.Get("Authorization")
		if rawAccessToken == "" {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		_, err := verifier.Verify(ctx, parts[1])
		log.Println(err)
		if err != nil {
			log.Println("error redirecting " + oauth2Config.AuthCodeURL(state))
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		log.Printf("Authenticated user")
		next.ServeHTTP(w, r)
	})
}

func (amw *AuthenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth2Config, state, verifier, ctx := AuthConfig()
		if r.URL.Query().Get("state") != state {
			log.Println("state did not match")
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Println("Failed to exchange token")
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Println("No id_token field in oauth2 token.")
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Println("Auth Failed to verify ID Token")
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			log.Println("Auth idToken claim error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			log.Println("Auth marshal indent error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		val, err := w.Write(data)
		if err != nil {
			log.Println("Auth write data error")
			http.Error(w, err.Error(), val)
			return
		}
	})
}
