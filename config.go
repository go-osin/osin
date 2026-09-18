package osin

import "slices"

// AllowedAuthorizeType is a collection of allowed auth request types
type AllowedAuthorizeType []AuthorizeRequestType

// Exists returns true if the auth type exists in the list
func (t AllowedAuthorizeType) Exists(rt AuthorizeRequestType) bool {
	return slices.Contains(t, rt)
}

// AllowedAccessType is a collection of allowed access request types
type AllowedAccessType []AccessRequestType

// Exists returns true if the access type exists in the list
func (t AllowedAccessType) Exists(rt AccessRequestType) bool {
	return slices.Contains(t, rt)
}

// ServerConfig contains server configuration information
type ServerConfig struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeTypes AllowedAuthorizeType

	// List of allowed access types (only AUTHORIZATION_CODE by default)
	AllowedAccessTypes AllowedAccessType

	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	ErrorStatusCode int

	// If true allows client secret also in params, else only in
	// Authorization header - default false
	AllowClientSecretInParams bool

	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool

	// Require PKCE for code flows for public OAuth clients - default false
	RequirePKCEForPublicClients bool

	// Separator to support multiple URIs in Client.GetRedirectUri().
	// If blank (the default), don't allow multiple URIs.
	RedirectUriSeparator string

	// RetainTokenAfter Refresh allows the server to retain the access and
	// refresh token for re-use - default false
	RetainTokenAfterRefresh bool

	// EnforceOAuth21 enables the OAuth 2.1 baseline for the authorization code
	// flow - default false. When true, code_challenge is required on
	// authorization requests, redirect URIs are matched exactly (loopback
	// hosts may use a different port), and clients without a secret may
	// authenticate at the token endpoint with the client_id request parameter
	// alone. Implicit and password grants, iss metadata, DPoP and mTLS are not
	// affected.
	EnforceOAuth21 bool
}

// NewServerConfig returns a new ServerConfig with default configuration
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration:   250,
		AccessExpiration:          3600,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     AllowedAuthorizeType{CODE},
		AllowedAccessTypes:        AllowedAccessType{AUTHORIZATION_CODE},
		ErrorStatusCode:           200,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   false,
		EnforceOAuth21:            false,
	}
}