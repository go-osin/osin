package osin

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// error returned when validation don't match
type UriValidationError string

func (e UriValidationError) Error() string {
	return string(e)
}

func newUriValidationError(msg string, base string, redirect string) UriValidationError {
	return UriValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// Parse urls, resolving uri references to base url
func ParseUrls(baseUrl, redirectUrl string) (retBaseUrl, retRedirectUrl *url.URL, err error) {
	var base, redirect *url.URL
	// parse base url
	if base, err = url.Parse(baseUrl); err != nil {
		return nil, nil, err
	}

	// parse redirect url
	if redirect, err = url.Parse(redirectUrl); err != nil {
		return nil, nil, err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, newUriValidationError("url must not include fragment.", baseUrl, redirectUrl)
	}

	// Scheme must match
	if redirect.Scheme != base.Scheme {
		return nil, nil, newUriValidationError("scheme mismatch", baseUrl, redirectUrl)
	}

	// Host must match
	if redirect.Host != base.Host {
		return nil, nil, newUriValidationError("host mismatch", baseUrl, redirectUrl)
	}

	// resolve references to base url
	retBaseUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: base.Path})
	retRedirectUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})
	return
}

// ValidateUriList validates that redirectUri is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func ValidateUriList(baseUriList string, redirectUri string, separator string) (realRedirectUri string, err error) {
	// make a list of uris
	var slist []string
	if separator != "" {
		slist = strings.Split(baseUriList, separator)
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseUriList)
	}

	for _, sitem := range slist {
		realRedirectUri, err = ValidateUri(sitem, redirectUri)
		// validated, return no error
		if err == nil {
			return realRedirectUri, nil
		}

		// if there was an error that is not a validation error, return it
		if _, ok := errors.AsType[UriValidationError](err); !ok {
			return "", err
		}
	}

	return "", newUriValidationError("urls don't validate", baseUriList, redirectUri)
}

// ValidateUri validates that redirectUri is contained in baseUri
func ValidateUri(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	if baseUri == "" || redirectUri == "" {
		return "", errors.New("urls cannot be blank")
	}

	base, redirect, err := ParseUrls(baseUri, redirectUri)
	if err != nil {
		return "", err
	}

	// allow exact path matches
	if base.Path == redirect.Path {
		return redirect.String(), nil
	}

	// ensure prefix matches are actually subpaths
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return "", newUriValidationError("path prefix doesn't match", baseUri, redirectUri)
	}

	return redirect.String(),nil
}

// Returns the first uri from an uri list
func FirstUri(baseUriList string, separator string) string {
	if separator != "" {
		slist := strings.Split(baseUriList, separator)
		if len(slist) > 0 {
			return slist[0]
		}
	} else {
		return baseUriList
	}

	return ""
}

// splitUriList makes a list of uris from a separator separated string.
// If separator is blank, the string is a single uri.
func splitUriList(baseUriList string, separator string) []string {
	if separator == "" {
		return []string{baseUriList}
	}
	return strings.Split(baseUriList, separator)
}

// clientHasRedirectUri reports whether a client registered any redirect uri,
// either as a set or as the single GetRedirectUri() value.
func clientHasRedirectUri(client Client) bool {
	if uriSet, ok := client.(ClientRedirectUriSet); ok && len(uriSet.GetRedirectUris()) > 0 {
		return true
	}
	return client.GetRedirectUri() != ""
}

// clientRedirectUris resolves how the redirect URIs registered for a client
// are used. It returns the registered uris and the validation to apply to a
// requested redirect_uri. Both come from the same resolution so a caller cannot
// pair a uri set with the wrong comparison.
//
// A client implementing ClientRedirectUriSet supplies the set itself: every
// entry is compared exactly, with the RFC 8252 §7.3 loopback port exception,
// and RedirectUriSeparator and EnforceOAuth21 are ignored. Every other client
// falls back to GetRedirectUri() split by RedirectUriSeparator, compared with
// the function EnforceOAuth21 selects.
func (s *Server) clientRedirectUris(client Client) (registered []string, validate func(redirectUri string) (string, error)) {
	if uriSet, ok := client.(ClientRedirectUriSet); ok {
		if uris := uriSet.GetRedirectUris(); len(uris) > 0 {
			return uris, func(redirectUri string) (string, error) {
				return validateUriExactList(uris, redirectUri)
			}
		}
	}

	registeredUri := client.GetRedirectUri()
	validateUri := ValidateUriList
	if s.Config.EnforceOAuth21 {
		validateUri = validateUriListExact
	}
	return splitUriList(registeredUri, s.Config.RedirectUriSeparator), func(redirectUri string) (string, error) {
		return validateUri(registeredUri, redirectUri, s.Config.RedirectUriSeparator)
	}
}

// validateUriExactList validates that redirectUri matches one of the registered
// uris exactly, keeping the loopback port exception of validateUriExact.
func validateUriExactList(registered []string, redirectUri string) (realRedirectUri string, err error) {
	for _, registeredUri := range registered {
		realRedirectUri, err = validateUriExact(registeredUri, redirectUri)
		// validated, return no error
		if err == nil {
			return realRedirectUri, nil
		}

		// if there was an error that is not a validation error, return it
		if _, ok := errors.AsType[UriValidationError](err); !ok {
			return "", err
		}
	}

	return "", newUriValidationError("urls don't validate exactly", strings.Join(registered, " "), redirectUri)
}

// validateUriListExact validates that redirectUri is contained in baseUriList
// using a simple string comparison.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func validateUriListExact(baseUriList string, redirectUri string, separator string) (realRedirectUri string, err error) {
	return validateUriExactList(splitUriList(baseUriList, separator), redirectUri)
}

// validateUriExact validates that redirectUri matches baseUri. The URIs must be
// equal as strings, except that http loopback hosts may use a port that differs
// from the registered one (https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
func validateUriExact(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	if baseUri == "" || redirectUri == "" {
		return "", errors.New("urls cannot be blank")
	}

	base, err := url.Parse(baseUri)
	if err != nil {
		return "", err
	}
	redirect, err := url.Parse(redirectUri)
	if err != nil {
		return "", err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return "", newUriValidationError("url must not include fragment.", baseUri, redirectUri)
	}

	if baseUri != redirectUri && !loopbackUriVariant(base, redirect) {
		return "", newUriValidationError("urls are not equal", baseUri, redirectUri)
	}

	return redirect.String(), nil
}

// loopbackUriVariant reports whether the two http URLs are equal once the port
// is removed from the loopback host that RFC 8252 §7.3 allows to differ.
func loopbackUriVariant(base *url.URL, redirect *url.URL) bool {
	if base.Scheme != "http" || redirect.Scheme != "http" {
		return false
	}

	host := base.Hostname()
	if host != redirect.Hostname() || (host != "127.0.0.1" && host != "::1") {
		return false
	}
	if base.Port() == redirect.Port() {
		return false
	}

	portlessBase, portlessRedirect := *base, *redirect
	portlessBase.Host, portlessRedirect.Host = host, host

	return portlessBase.String() == portlessRedirect.String()
}
