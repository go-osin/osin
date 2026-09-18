package osin

import (
	"encoding/base64"
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

// CheckClientSecret determines whether the given secret matches a secret held by the client.
// Public clients return true for a secret of ""
func CheckClientSecret(client Client, secret string) bool {
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
	// TODO: migrate to r.BasicAuth()
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	kind, encoded, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || kind != "Basic" {
		return nil, errors.New("invalid authorization header")
	}

	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	user, pass, ok := strings.Cut(string(b), ":")
	if !ok {
		return nil, errors.New("invalid authorization message")
	}

	// Decode the client_id and client_secret pairs as per
	// https://tools.ietf.org/html/rfc6749#section-2.3.1

	username, err := url.QueryUnescape(user)
	if err != nil {
		return nil, err
	}

	password, err := url.QueryUnescape(pass)
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
	username, password, baOk := r.BasicAuth()
	if baOk {
		// If BasicAuth header is present, the client secret (password) must not be empty.
		// This is required for standard Basic Authentication.
		if password == "" {
			s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("empty client secret"), "get_client_auth=%s", "check auth error")
			return nil
		}
		return &BasicAuth{
			Username: username,
			Password: password,
		}
	}

	// If no BasicAuth header found, optionally fall back to form parameters.
	if allowQueryParams {
		username = r.FormValue("client_id")
		password = r.FormValue("client_secret")
		if username != "" {
			// In form parameters, client_secret may be empty (e.g. OAuth2 PKCE flow).
			return &BasicAuth{
				Username: username,
				Password: password,
			}
		}
	}

	// No valid client authentication provided
	s.setErrorAndLog(w, E_INVALID_REQUEST, errors.New("Client authentication not sent"), "get_client_auth=%s", "client authentication not sent")
	return nil
}