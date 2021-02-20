package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Ubivius/microservice-template/handlers"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/exporters/stdout"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/oauth2"
)

func main() {
	// Logger
	logger := log.New(os.Stdout, "Template", log.LstdFlags)

	// Initialising open telemetry

	// Creating console exporter
	exporter, err := stdout.NewExporter(
		stdout.WithPrettyPrint(),
	)
	if err != nil {
		logger.Fatal("Failed to initialize stdout export pipeline : ", err)
	}

	// Creating tracer provider
	ctx := context.Background()
	batchSpanProcessor := sdktrace.NewBatchSpanProcessor(exporter)
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(batchSpanProcessor))
	defer func() { _ = tracerProvider.Shutdown(ctx) }()

	// Creating handlers
	productHandler := handlers.NewProductsHandler(logger)

	// Mux route handling with gorilla/mux
	router := mux.NewRouter()

	//Authentication setup
	configURL := "http://localhost:8080/auth/realms/ubivius"
	ctx = context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		logger.Println("Auth panic")
		panic(err)
	}

	clientID := "ubivius-client"
	clientSecret := "ef14f638-98ad-4c5b-9320-a223077e0797"

	redirectURL := "http://localhost:9090/ubivius/callback"
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	state := "somestate"

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)
	authRouter := router.Methods(http.MethodGet).Subrouter()
	//Auth router
	authRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		logger.Println(err)
		if err != nil {
			logger.Println("error redirecting " + oauth2Config.AuthCodeURL(state))
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		val, err := w.Write([]byte("hello world"))
		if err != nil {
			logger.Println("error writing hello world")
			http.Error(w, err.Error(), val)
			return
		}
	})

	authRouter.HandleFunc("/ubivius/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			logger.Println("state did not match")
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			logger.Println("Failed to exchange token")
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Println("No id_token field in oauth2 token.")
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			logger.Println("Auth Failed to verify ID Token")
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			logger.Println("Auth idToken claim error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			logger.Println("Auth marshal indent error")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		val, err := w.Write(data)
		if err != nil {
			logger.Println("Auth write data error")
			http.Error(w, err.Error(), val)
			return
		}
	})

	// Get Router
	getRouter := router.Methods(http.MethodGet).Subrouter()
	getRouter.HandleFunc("/products", productHandler.GetProducts)
	getRouter.HandleFunc("/products/{id:[0-9]+}", productHandler.GetProductByID)

	// Put router
	putRouter := router.Methods(http.MethodPut).Subrouter()
	putRouter.HandleFunc("/products", productHandler.UpdateProducts)
	putRouter.Use(productHandler.MiddlewareProductValidation)

	// Post router
	postRouter := router.Methods(http.MethodPost).Subrouter()
	postRouter.HandleFunc("/products", productHandler.AddProduct)
	postRouter.Use(productHandler.MiddlewareProductValidation)

	// Delete router
	deleteRouter := router.Methods(http.MethodDelete).Subrouter()
	deleteRouter.HandleFunc("/products/{id:[0-9]+}", productHandler.Delete)

	// Server setup
	server := &http.Server{
		Addr:        ":9090",
		Handler:     router,
		IdleTimeout: 120 * time.Second,
		ReadTimeout: 1 * time.Second,
	}

	go func() {
		logger.Println("Starting server on port ", server.Addr)
		err := server.ListenAndServe()
		if err != nil {
			logger.Println("Error starting server : ", err)
			logger.Fatal(err)
		}
	}()

	// Handle shutdown signals from operating system
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	receivedSignal := <-signalChannel

	logger.Println("Received terminate, beginning graceful shutdown", receivedSignal)

	// Server shutdown
	timeoutContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = server.Shutdown(timeoutContext)
}
