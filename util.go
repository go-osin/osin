package osin

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Parse basic authentication header
type BasicAuth struct {
	Username string
	Password string
}

// Parse bearer authentication header
type BearerAuth struct {
	Code string
}

// clientSecretUse says how the shared secret of a client takes part in token
// endpoint authentication.
type clientSecretUse int

const (
	// clientUsesSharedSecret - the client authenticates with a shared secret,
	// either through the legacy GetSecret()/ClientSecretMatcher path (the
	// client did not declare a method) or through one of the client_secret_*
	// methods.
	clientUsesSharedSecret clientSecretUse = iota

	// clientUsesNoSecret - the client declared the `none` method and identifies
	// itself with the client_id request parameter alone.
	clientUsesNoSecret

	// clientUsesOtherCredential - the client declared a method whose
	// credentials are not a shared secret (private_key_jwt, tls_client_auth,
	// client_secret_jwt, and any method this version does not know).
	clientUsesOtherCredential
)

// clientSecretUseOf resolves how a client uses a shared secret. Clients that
// declare no method keep the previous behaviour, where a blank secret means a
// public client.
func clientSecretUseOf(client Client) clientSecretUse {
	authMethod, ok := client.(ClientAuthMethod)
	if !ok {
		return clientUsesSharedSecret
	}

	switch authMethod.GetAuthMethod() {
	case "":
		return clientUsesSharedSecret
	case AUTH_METHOD_NONE:
		return clientUsesNoSecret
	case AUTH_METHOD_CLIENT_SECRET_POST, AUTH_METHOD_CLIENT_SECRET_BASIC:
		return clientUsesSharedSecret
	default:
		return clientUsesOtherCredential
	}
}

// CheckClientSecret determines whether the given secret matches a secret held by the client.
// Public clients return true for a secret of ""
func CheckClientSecret(client Client, secret string) bool {
	switch clientSecretUseOf(client) {
	case clientUsesNoSecret:
		// A client without a shared secret is identified by the client_id alone
		return secret == ""
	case clientUsesOtherCredential:
		// The client declared credentials that this comparison cannot check,
		// so no shared secret matches
		return false
	}

	return clientSecretMatches(client, secret)
}

// clientSecretMatches compares the secret held by the client, ignoring the
// declared token endpoint authentication method.
func clientSecretMatches(client Client, secret string) bool {
	switch client := client.(type) {
	case ClientSecretMatcher:
		// Prefer the more secure method of giving the secret to the client for comparison
		return client.ClientSecretMatches(secret)
	default:
		// Fallback to the less secure method of extracting the plain text secret from the client for comparison
		return client.GetSecret() == secret
	}
}

// Return authorization header data
func CheckBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("invalid authorization header")
	}

	// Decode the client_id and client_secret pairs as per
	// https://tools.ietf.org/html/rfc6749#section-2.3.1

	username, err := url.QueryUnescape(username)
	if err != nil {
		return nil, err
	}

	password, err = url.QueryUnescape(password)
	if err != nil {
		return nil, err
	}

	return &BasicAuth{Username: username, Password: password}, nil
}

// Return "Bearer" token from request. The header has precedence over query string.
func CheckBearerAuth(r *http.Request) *BearerAuth {
	authHeader := r.Header.Get("Authorization")
	authForm := r.FormValue("code")
	if authHeader == "" && authForm == "" {
		return nil
	}

	token := authForm
	if authHeader != "" {
		kind, value, ok := strings.Cut(authHeader, " ")
		//Use authorization header token only if token type is bearer else query string access token would be returned
		bearer := ok && value != "" && strings.EqualFold(kind, "bearer")
		if !bearer && token == "" {
			return nil
		}
		if bearer {
			token = value
		}
	}
	return &BearerAuth{Code: token}
}

// getClientAuth checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func (s *Server) getClientAuth(w *Response, r *http.Request, allowQueryParams bool) *BasicAuth {
	if allowQueryParams {
		// Allow for auth without password
		if username := r.FormValue("client_id"); username != "" {
			if _, hasSecret := r.Form["client_secret"]; hasSecret {
				return &BasicAuth{
					Username: username,
					Password: r.FormValue("client_secret"),
				}
			}
		}
	}

	auth, err := CheckBasicAuth(r)
	if err != nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, err, "get_client_auth=%s", "check auth error")
		return nil
	}
	if auth != nil {
		// If the Authorization header is present, the client secret (password)
		// must not be empty. This is required for standard Basic Authentication.
		if auth.Password == "" {
			s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("empty client secret"), "get_client_auth=%s", "check auth error")
			return nil
		}
		return auth
	}

	// No credentials were sent: clients without a shared secret identify
	// themselves with the client_id parameter alone. That is a 2.1 client
	// when EnforceOAuth21 is set, and a client that declared the `none`
	// token endpoint authentication method in any configuration.
	if username := r.FormValue("client_id"); username != "" {
		if s.Config.EnforceOAuth21 || clientIdentifiesWithIDOnly(w.Storage, username) {
			return &BasicAuth{
				Username: username,
			}
		}
	}

	// No valid client authentication provided
	s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Client authentication not sent"), "get_client_auth=%s", "client authentication not sent")
	return nil
}

// clientIdentifiesWithIDOnly reports whether the client stored under id
// declared the `none` token endpoint authentication method, which lets it
// authenticate with the client_id request parameter alone.
func clientIdentifiesWithIDOnly(storage Storage, id string) bool {
	if storage == nil {
		// a response without storage cannot resolve the client
		return false
	}
	client, err := storage.GetClient(id)
	if err != nil || client == nil {
		return false
	}
	return clientSecretUseOf(client) == clientUsesNoSecret
}
