package osin

// Client information
type Client interface {
	// Client id
	GetId() string

	// Client secret
	GetSecret() string

	// Base client uri
	GetRedirectUri() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() any
}

// ClientSecretMatcher is an optional interface clients can implement
// which allows them to be the one to determine if a secret matches.
// If a Client implements ClientSecretMatcher, the framework will never call GetSecret
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	ClientSecretMatches(secret string) bool
}

// TokenEndpointAuthMethod is a client's token endpoint authentication method,
// with the values registered in the IANA token_endpoint_auth_method registry
// (rfc7591). Values outside the constants below are used as they are, and the
// zero value means the client did not declare a method.
type TokenEndpointAuthMethod string

const (
	// AUTH_METHOD_NONE - the client has no shared secret and identifies itself
	// with the client_id request parameter alone.
	AUTH_METHOD_NONE TokenEndpointAuthMethod = "none"

	// AUTH_METHOD_CLIENT_SECRET_POST - the client authenticates with its
	// shared secret as a request parameter.
	AUTH_METHOD_CLIENT_SECRET_POST TokenEndpointAuthMethod = "client_secret_post"

	// AUTH_METHOD_CLIENT_SECRET_BASIC - the client authenticates with its
	// shared secret through HTTP Basic authentication.
	AUTH_METHOD_CLIENT_SECRET_BASIC TokenEndpointAuthMethod = "client_secret_basic"

	// AUTH_METHOD_CLIENT_SECRET_JWT - the client authenticates with a JWT
	// signed with its shared secret.
	AUTH_METHOD_CLIENT_SECRET_JWT TokenEndpointAuthMethod = "client_secret_jwt"

	// AUTH_METHOD_PRIVATE_KEY_JWT - the client authenticates with a JWT signed
	// with a private key.
	AUTH_METHOD_PRIVATE_KEY_JWT TokenEndpointAuthMethod = "private_key_jwt"

	// AUTH_METHOD_TLS_CLIENT_AUTH - the client authenticates with a TLS client
	// certificate.
	AUTH_METHOD_TLS_CLIENT_AUTH TokenEndpointAuthMethod = "tls_client_auth"
)

// ClientRedirectUriSet is an optional interface clients can implement to
// expose the redirect URIs they registered as a set. When it returns a
// non-empty set, the authorization and token endpoints compare the requested
// redirect_uri against every entry exactly (with the RFC 8252 §7.3 loopback
// port exception), ignoring both RedirectUriSeparator and EnforceOAuth21.
type ClientRedirectUriSet interface {
	// GetRedirectUris returns the registered redirect URIs. An empty result
	// falls back to GetRedirectUri().
	GetRedirectUris() []string
}

// ClientAuthMethod is an optional interface clients can implement to declare
// how they authenticate at the token endpoint. Without it, the library falls
// back to GetSecret() and ClientSecretMatcher.
type ClientAuthMethod interface {
	// GetAuthMethod returns the registered token endpoint authentication
	// method.
	GetAuthMethod() TokenEndpointAuthMethod
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	Id          string
	Secret      string
	RedirectUri string
	UserData    any

	// RedirectUris lists the redirect URIs registered for the client. A
	// non-empty list takes precedence over RedirectUri.
	RedirectUris []string

	// AuthMethod declares how the client authenticates at the token endpoint.
	// The zero value falls back to Secret.
	AuthMethod TokenEndpointAuthMethod
}

func (d *DefaultClient) GetId() string {
	return d.Id
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetRedirectUri() string {
	return d.RedirectUri
}

func (d *DefaultClient) GetUserData() any {
	return d.UserData
}

// Implement the ClientSecretMatcher interface
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}

// Implement the ClientRedirectUriSet interface
func (d *DefaultClient) GetRedirectUris() []string {
	return d.RedirectUris
}

// Implement the ClientAuthMethod interface
func (d *DefaultClient) GetAuthMethod() TokenEndpointAuthMethod {
	return d.AuthMethod
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.Id = client.GetId()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectUri()
	d.UserData = client.GetUserData()
	d.RedirectUris = nil
	if uriSet, ok := client.(ClientRedirectUriSet); ok {
		d.RedirectUris = uriSet.GetRedirectUris()
	}
	d.AuthMethod = ""
	if authMethod, ok := client.(ClientAuthMethod); ok {
		d.AuthMethod = authMethod.GetAuthMethod()
	}
}
