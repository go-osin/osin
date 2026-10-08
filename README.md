OSIN
====

[![GoDoc](https://godoc.org/github.com/RangelReale/osin?status.svg)](https://godoc.org/github.com/RangelReale/osin)


Golang OAuth2 server library
----------------------------

OSIN is an OAuth2 server library for the Go language, as specified at
http://tools.ietf.org/html/rfc6749 and http://tools.ietf.org/html/draft-ietf-oauth-v2-10.

It also includes support for PKCE, as specified at https://tools.ietf.org/html/rfc7636,
which increases security for code-exchange flows for public OAuth clients.

Setting `EnforceOAuth21` on `ServerConfig` (default `false`) turns the authorization code
flow into the OAuth 2.1 baseline: `code_challenge` is required on authorization requests,
the issued code can only be exchanged with a matching `code_verifier`, `redirect_uri` must
match a registered URI exactly including the query string (loopback hosts registered as
`http://127.0.0.1` or `http://[::1]` may use a different port, per RFC 8252), and clients
that have no secret may identify themselves at the token endpoint with the request body
`client_id` alone, regardless of `AllowClientSecretInParams`. Clients holding a secret must
still authenticate. Implicit and password grants, `iss` metadata, DPoP and mTLS are not
affected by this flag.

### OAuth 2.1 client registration and token binding

The `Client` and `Storage` method sets are unchanged, so existing implementations keep compiling
and behaving as before. Everything below is additive and opt-in.

**Redirect URI sets.** A client may implement `ClientRedirectUriSet`:

````go
func (c *CimdClient) GetRedirectUris() []string { return c.metadata.RedirectURIs }
````

When it returns a non-empty set, the authorization and token endpoints compare the requested
`redirect_uri` against every entry of that set exactly, keeping the RFC 8252 loopback port
exception for `http://127.0.0.1` and `http://[::1]`. Neither `RedirectUriSeparator` nor
`EnforceOAuth21` applies to such a client: registering a set is what selects exact matching. A
client that returns no set keeps using `GetRedirectUri()` and the existing rules.

**Token endpoint authentication method.** A client may implement `ClientAuthMethod`:

````go
func (c *CimdClient) GetAuthMethod() osin.TokenEndpointAuthMethod { return osin.AUTH_METHOD_NONE }
````

An `AUTH_METHOD_NONE` client identifies itself at the token endpoint with the `client_id`
parameter alone, even when `GetSecret()` returns a non-empty string, regardless of
`AllowClientSecretInParams`. A client that declares any other method never authenticates through
a shared secret: `private_key_jwt`, `tls_client_auth` and `client_secret_jwt` clients are rejected
at the token endpoint instead of being treated as public clients. A client that declares nothing
keeps the previous rule, where a blank `GetSecret()` means a public client. `DefaultClient`
implements both optional interfaces through its `RedirectUris` and `AuthMethod` fields.

**Issuer.** Setting `ServerConfig.Issuer` makes authorization responses carry the `iss` parameter
(RFC 9207), in the query of code responses and in the fragment of implicit responses. It is
omitted while the field is blank, and it is never added to token responses or to data errors.

**Rejecting `plain` PKCE.** RFC 9700 requires authorization servers to support PKCE, not to refuse
the `plain` method, so refusing it is a deployment choice: setting `ServerConfig.RejectPlainPKCE`
rejects authorization requests that explicitly use `code_challenge_method=plain` and those that
omit the parameter, which RFC 7636 defaults to `plain`.

**Sender constrained tokens.** `AccessData.SenderConstraint` carries the binding of a token to the
key material the client demonstrated at the token endpoint (a DPoP JWK thumbprint, an mTLS
certificate thumbprint, ...); its zero value means the token is not bound. The library does not
perform the proof or certificate validation itself, and it does not choose the binding: the
integration writes `AccessData.SenderConstraint` from its `AccessTokenGen.GenerateAccessToken`
before the record reaches the storage, or supplies the whole record through
`AccessRequest.ForceAccessData`. Setting
`ServerConfig.RequireSenderConstrainedTokens` rejects refresh token exchanges and access token
lookups whose stored token has no binding, so a storage that drops the field on the way in turns
into a visible `invalid_grant` rather than an unconstrained token. Such a deployment must also
implement `SenderConstraintStorage` on the storage; without it, issuing a token fails with
`server_error`.

None of this requires downstream changes: `Client` and `Storage` gained no methods, and the new
`ServerConfig` fields default to the current behavior. The one build breakage Go does not exclude
is the usual one for exported structs gaining fields: unkeyed struct literals of `DefaultClient`,
`AccessData`, `ServerConfig` and `Response` must be given field names.

Using it, you can build your own OAuth2 authentication service.

The library implements the majority of the specification, like authorization and token endpoints, and authorization code, implicit, resource owner and client credentials grant types.

### Example Server

````go
import (
	"github.com/RangelReale/osin"
	ex "github.com/RangelReale/osin/example" 
)

// ex.NewTestStorage implements the "osin.Storage" interface
server := osin.NewServer(osin.NewServerConfig(), ex.NewTestStorage())

// Authorization code endpoint
http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {

		// HANDLE LOGIN PAGE HERE

		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

// Access token endpoint
http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

http.ListenAndServe(":14000", nil)
````

### Example Access

Open in your web browser:

````
http://localhost:14000/authorize?response_type=code&client_id=1234&redirect_uri=http%3A%2F%2Flocalhost%3A14000%2Fappauth%2Fcode
````

### Storage backends

There is a mock available at [example/teststorage.go](/example/teststorage.go) which you can use as a guide for writing your own.  

You might want to check out other implementations for common database management systems as well:

* [PostgreSQL](https://github.com/ory-am/osin-storage)
* [MongoDB](https://github.com/martint17r/osin-mongo-storage)
* [RethinkDB](https://github.com/ahmet/osin-rethinkdb)
* [DynamoDB](https://github.com/uniplaces/osin-dynamodb)
* [Couchbase](https://github.com/elgris/osin-couchbase-storage)
* [MySQL](https://github.com/felipeweb/osin-mysql)
* [Redis](https://github.com/ShaleApps/osinredis)

### License

The code is licensed using "New BSD" license.

### Author

Rangel Reale
rangelreale@gmail.com

### Changes

2014-06-25
==========
* BREAKING CHANGES:
	- Storage interface has 2 new methods, Clone and Close, to better support storages
	  that need to clone / close in each connection (mgo)
	- Client was changed to be an interface instead of an struct. Because of that,
	  the Storage interface also had to change, as interface is already a pointer.

	- HOW TO FIX YOUR CODE:
		+ In your Storage, add a Clone function returning itself, and a do nothing Close.
		+ In your Storage, replace all *osin.Client with osin.Client (remove the pointer reference)
		+ If you used the osin.Client struct directly in your code, change it to osin.DefaultClient,
		  which is a struct with the same fields that implements the interface.
		+ Change all accesses using osin.Client to use the methods instead of the fields directly.
		+ You MUST defer Response.Close in all your http handlers, otherwise some
		  Storages may not clean correctly.

				resp := server.NewResponse()
				defer resp.Close()
