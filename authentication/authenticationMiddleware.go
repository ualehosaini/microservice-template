package authentication

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

func (amw *AuthenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth2Config, state, verifier, ctx := AuthConfig()
		rawAccessToken := r.Header.Get("Authorization")
		log.Println("rawAccessToken: " + rawAccessToken)
		if rawAccessToken == "" {
			log.Println("No access token provided")
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
		log.Println("serving http")
		next.ServeHTTP(w, r)
		val, err := w.Write([]byte("hello world"))
		if err != nil {
			log.Println("error writing hello world")
			http.Error(w, err.Error(), val)
			return
		}
	})
}

func AuthCallback(responseWriter http.ResponseWriter, request *http.Request) {
	oauth2Config, state, verifier, ctx := AuthConfig()
	if request.URL.Query().Get("state") != state {
		log.Println("state did not match")
		http.Error(responseWriter, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, request.URL.Query().Get("code"))
	if err != nil {
		log.Println("Failed to exchange token")
		http.Error(responseWriter, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token field in oauth2 token.")
		http.Error(responseWriter, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Println("Auth Failed to verify ID Token")
		http.Error(responseWriter, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		log.Println("Auth idToken claim error")
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		log.Println("Auth marshal indent error")
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}

	val, err := responseWriter.Write(data)
	if err != nil {
		log.Println("Auth write data error")
		http.Error(responseWriter, err.Error(), val)
		return
	}
}
