package singpass

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

var (
	ErrNoEncKeyFound        = fmt.Errorf("no enc key found")
	ErrNoSigKeyFound        = fmt.Errorf("no sig key found")
	ErrUnsupportedAlgorithm = fmt.Errorf("invalid alg")
	ErrStateMismatch        = fmt.Errorf("state mismatch")
	ErrMissingCode          = fmt.Errorf("missing code")
	ErrCreateClaims         = fmt.Errorf("jwt.NewWithClaims")
	ErrExchange             = fmt.Errorf("exchange failed")
	ErrNoIDToken            = fmt.Errorf("no id_token")
	ErrParseEncrypted       = fmt.Errorf("jose.ParseEncrypted failed")
	ErrJWEDecrypt           = fmt.Errorf("jwe.Decrypt failed")
	ErrVerify               = fmt.Errorf("verify failed")
	ErrExtractNRIC          = fmt.Errorf("cannot extract nric and uuid")
	ErrInvalidSubPayload    = fmt.Errorf("token payload sub property is invalid, does not contain valid NRIC and uuid string")
)

// NonceState is a pair of nonce and state; things we keep track of before sending the user to singpass.
type NonceState struct {
	Nonce string
	State string
}

const nonceStateCookieName = "singpass_nonce_state"

// NonceStateToCookie sets a cookie with the given NonceState.
func NonceStateToCookie(w http.ResponseWriter) (NonceState, error) {
	var ret NonceState
	bigint, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return ret, err
	}

	state := bigint.Text(62)
	http.SetCookie(w, &http.Cookie{
		Name:     nonceStateCookieName,
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // redirecting back from oauth provider
	})
	return NonceState{Nonce: strconv.FormatInt(time.Now().UnixMilli(), 10), State: state}, nil
}

// StateFromCookie returns the state from the given request's cookie, previously set by NonceStateToCookie.
func StateFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(nonceStateCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

type httpErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// RedirectToSingpass returns a http.HandlerFunc that redirects the user to singpass.
func RedirectToSingpass(
	oauth2Config oauth2.Config,
	generateNonceState func(w http.ResponseWriter) (NonceState, error),
	errHandler httpErrorHandler,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		generated, err := generateNonceState(w)
		if err != nil {
			errHandler(w, r, err)
			return
		}
		http.Redirect(w, r, oauth2Config.AuthCodeURL(generated.State, oauth2.SetAuthURLParam("nonce", generated.Nonce)), http.StatusSeeOther)
	}
}

func keyForUse(jwks jose.JSONWebKeySet, use string) *jose.JSONWebKey {
	for _, key := range jwks.Keys {
		if key.Use == use {
			return &key
		}
	}
	return nil
}

// CallbackFromSingpass returns a http.HandlerFunc that can be used as a callback for OAuth2 flow.
// singpassBaseURL is `provider.issuer`, see https://stg-id.singpass.gov.sg/docs/authorization/api#_jwt_claims
func CallbackFromSingpass(
	singpassBaseURL string,
	provider *oidc.Provider,
	secretKeySet jose.JSONWebKeySet,
	oauth2Config oauth2.Config,
	getState func(r *http.Request) string,
	errHandler httpErrorHandler,
	okHandler func(w http.ResponseWriter, r *http.Request, payload NRICAndUUID),
) (http.HandlerFunc, error) {
	encJwk := keyForUse(secretKeySet, "enc")
	if encJwk == nil {
		return nil, ErrNoEncKeyFound
	}

	sigJwk := keyForUse(secretKeySet, "sig")
	if sigJwk == nil {
		return nil, ErrNoSigKeyFound
	}
	var signingMethod jwt.SigningMethod
	switch sigJwk.Algorithm {
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	default:
		// https://stg-id.singpass.gov.sg/docs/authorization/api#_jwt_header
		return nil, errors.Join(ErrUnsupportedAlgorithm, errors.New(sigJwk.Algorithm))
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		state := getState(r)
		if state != r.URL.Query().Get("state") {
			errHandler(w, r, ErrStateMismatch)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errHandler(w, r, ErrMissingCode)
			return
		}

		now := time.Now()
		jwtString, err := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
			// https://stg-id.singpass.gov.sg/docs/authorization/api#_jwt_claims
			"iss": oauth2Config.ClientID,
			"aud": singpassBaseURL,
			"sub": oauth2Config.ClientID,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(), // not longer than 2 minutes
		}).SignedString(sigJwk.Key)
		if err != nil {
			errHandler(w, r, errors.Join(ErrCreateClaims, err))
			return
		}

		// https://stg-id.singpass.gov.sg/docs/authorization/api#_authorization_code_grant_authenticated_with_client_assertion_jwt
		oauth2Token, err := oauth2Config.Exchange(ctx, code,
			oauth2.SetAuthURLParam("client_id", oauth2Config.ClientID),
			oauth2.SetAuthURLParam("client_assertion", jwtString),
			oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		)
		if err != nil {
			errHandler(w, r, errors.Join(ErrExchange, err))
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			errHandler(w, r, ErrNoIDToken)
			return
		}

		// decrypt the id token
		jwe, err := jose.ParseEncrypted(rawIDToken)
		if err != nil {
			errHandler(w, r, errors.Join(ErrParseEncrypted, err))
			return
		}
		decryptedIDToken, err := jwe.Decrypt(encJwk.Key)
		if err != nil {
			errHandler(w, r, errors.Join(ErrJWEDecrypt, err))
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := provider.Verifier(&oidc.Config{
			SupportedSigningAlgs: []string{sigJwk.Algorithm},
			ClientID:             oauth2Config.ClientID,
		}).Verify(ctx, string(decryptedIDToken))
		if err != nil {
			errHandler(w, r, errors.Join(ErrVerify, err))
			return
		}
		payload, err := ExtractNRICAndUUIDFromPayload(idToken.Subject)
		if err != nil {
			errHandler(w, r, errors.Join(ErrExtractNRIC, err))
			return
		}
		okHandler(w, r, payload)
	}, nil
}

// NRICAndUUID is a pair of NRIC and UUID.
type NRICAndUUID struct {
	NRIC string
	UUID string
}

var extractionRegex = regexp.MustCompile(`s=([STFGM]\d{7}[A-Z]).*,u=(.*)`)

// ExtractNRICAndUUIDFromPayload extracts NRIC and UUID from the given payload's 'sub' property.
// converted from `extractNricAndUuidFromPayload` in https://github.com/GovTechSG/singpass-myinfo-oidc-helper
func ExtractNRICAndUUIDFromPayload(sub string) (NRICAndUUID, error) {
	var ret NRICAndUUID
	matchResult := extractionRegex.FindStringSubmatch(sub)
	if matchResult == nil {
		return ret, ErrInvalidSubPayload
	}
	return NRICAndUUID{NRIC: matchResult[1], UUID: matchResult[2]}, nil
}
