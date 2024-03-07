package internal

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/choonkeat-govtech/singpass"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"golang.org/x/oauth2"
)

func CompileCheck() error {
	//
	// Some setup
	//
	var provider oidc.Provider
	cfg := oauth2.Config{
		ClientID:    `CLIENT_ID`,
		RedirectURL: `http://myserver.com/mysingpass/callback`,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID},
	}
	var secretKeySet jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(`{"keys":[{"kty":"EC"...,"alg":"ECDH-ES+A256KW"}]}`), &secretKeySet); err != nil {
		return fmt.Errorf("json.Unmarshal jose.JSONWebKeySet: %w", err)
	}
	singpassCallbackHandler, err := singpass.CallbackFromSingpass(
		"https://id.singpass.gov.sg",
		&provider,
		secretKeySet,
		cfg,
		singpass.StateFromCookie,
		handleError,
		handleSuccess,
	)
	if err != nil {
		return fmt.Errorf("singpass.CallbackFromSingpass: %w", err)
	}

	//
	// Use as http handlers
	//
	http.HandleFunc("/mysingpass/start", singpass.RedirectToSingpass(cfg, singpass.NonceStateToCookie, handleError))
	http.HandleFunc("/mysingpass/callback", singpassCallbackHandler)
	http.HandleFunc("/mysingpass/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[{"kty":"EC"...,"alg":"ECDH-ES+A256KW"}]}`))
	})
	return nil
}

func handleError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func handleSuccess(w http.ResponseWriter, _ *http.Request, payload singpass.NRICAndUUID) {
	w.Write([]byte(fmt.Sprintf("Success! %#v", payload)))
}
