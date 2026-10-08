package osin

import (
	"testing"
)

func TestURIValidate(t *testing.T) {
	valid := [][]string{
		{
			// Exact match
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauth",
		},
		{
			// Trailing slash
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			// Exact match with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/",
		},
		{
			// Subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with trailing slash
			"http://www.google.com/myapp/",
			"http://www.google.com/myapp/interface/implementation",
			"http://www.google.com/myapp/interface/implementation",
		},
		{
			// Subpath with things that are close to path traversals, but aren't
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/.../..implementation../...",
			"http://www.google.com/myapp/.../..implementation../...",
		},
		{
			// If the allowed basepath contains path traversals, allow them?
			"http://www.google.com/traversal/../allowed",
			"http://www.google.com/traversal/../allowed/with/subpath",
			"http://www.google.com/allowed/with/subpath",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure/redirect/\\../\\../\\../evil",
			"https://mysafewebsite.com/secure/redirect/%5C../%5C../%5C../evil",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure/redirect/\\..\\../\\../evil",
			"https://mysafewebsite.com/secure/redirect/%5C..%5C../%5C../evil",
		},
		{
			// Query string must be kept
			"http://www.google.com/myapp/redir",
			"http://www.google.com/myapp/redir?a=1&b=2",
			"http://www.google.com/myapp/redir?a=1&b=2",
		},
	}
	for _, v := range valid {
		if realRedirectUri, err := ValidateUri(v[0], v[1]); err != nil {
			t.Errorf("Expected ValidateUri(%s, %s) to succeed, got %v", v[0], v[1], err)
		} else if len(v) == 3 && realRedirectUri != v[2] {
			t.Errorf("Expected ValidateUri(%s, %s) to return uri %s, got %s", v[0], v[1], v[2], realRedirectUri)
		}
	}

	invalid := [][]string{
		{
			// Doesn't satisfy base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/app",
		},
		{
			// Doesn't satisfy base path
			"http://localhost:14000/app/",
			"http://localhost:14000/app",
		},
		{
			// Not a subpath of base path
			"http://localhost:14000/appauth",
			"http://localhost:14000/appauthmodifiedpath",
		},
		{
			// Host mismatch
			"http://www.google.com/myapp",
			"http://www2.google.com/myapp",
		},
		{
			// Scheme mismatch
			"http://www.google.com/myapp",
			"https://www.google.com/myapp",
		},
		{
			// Path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/..",
		},
		{
			// Embedded path traversal
			"http://www.google.com/myapp",
			"http://www.google.com/myapp/../test",
		},
		{
			// Not a subpath
			"http://www.google.com/myapp",
			"http://www.google.com/myapp../test",
		},
		{
			// Backslashes
			"https://mysafewebsite.com/secure/redirect",
			"https://mysafewebsite.com/secure%2fredirect/../evil",
		},
	}
	for _, v := range invalid {
		if _, err := ValidateUri(v[0], v[1]); err == nil {
			t.Errorf("Expected ValidateUri(%s, %s) to fail", v[0], v[1])
		}
	}
}

func TestURIListValidate(t *testing.T) {
	// V1
	if _, err := ValidateUriList("http://localhost:14000/appauth", "http://localhost:14000/appauth", ""); err != nil {
		t.Errorf("V1: %s", err)
	}

	// V2
	if _, err := ValidateUriList("http://localhost:14000/appauth", "http://localhost:14000/app", ""); err == nil {
		t.Error("V2 should have failed")
	}

	// V3
	if _, err := ValidateUriList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/appauth", ";"); err != nil {
		t.Errorf("V3: %s", err)
	}

	// V4
	if _, err := ValidateUriList("http://xxx:14000/appauth;http://localhost:14000/appauth", "http://localhost:14000/app", ";"); err == nil {
		t.Error("V4 should have failed")
	}
}

func TestValidateUriListExact(t *testing.T) {
	valid := [][]string{
		{
			// Exact match
			"https://app.example.com/cb",
			"https://app.example.com/cb",
			"https://app.example.com/cb",
		},
		{
			// Exact match with query
			"https://app.example.com/cb?x=1",
			"https://app.example.com/cb?x=1",
			"https://app.example.com/cb?x=1",
		},
		{
			// Loopback hosts may use a different port
			"http://127.0.0.1/cb",
			"http://127.0.0.1:49152/cb",
			"http://127.0.0.1:49152/cb",
		},
		{
			// Loopback IPv6 hosts may use a different port
			"http://[::1]/cb",
			"http://[::1]:49152/cb",
			"http://[::1]:49152/cb",
		},
	}
	for _, v := range valid {
		if realRedirectUri, err := validateUriListExact(v[0], v[1], ""); err != nil {
			t.Errorf("Expected validateUriListExact(%s, %s) to succeed, got %v", v[0], v[1], err)
		} else if realRedirectUri != v[2] {
			t.Errorf("Expected validateUriListExact(%s, %s) to return uri %s, got %s", v[0], v[1], v[2], realRedirectUri)
		}
	}

	invalid := [][]string{
		{
			// Subpath must not be accepted
			"https://app.example.com/cb",
			"https://app.example.com/cb/extra",
		},
		{
			// Not a subpath relation in either direction
			"https://app.example.com/cb",
			"https://app.example.com/other/cb",
		},
		{
			// Query must match
			"https://app.example.com/cb",
			"https://app.example.com/cb?x=1",
		},
		{
			// Query values must match
			"https://app.example.com/cb?x=1",
			"https://app.example.com/cb?x=2",
		},
		{
			// Non-loopback hosts may not change the port
			"https://app.example.com/cb",
			"https://app.example.com:8443/cb",
		},
		{
			// The loopback exception does not relax the path
			"http://127.0.0.1/cb",
			"http://127.0.0.1:49152/cb/extra",
		},
		{
			// localhost is not covered by the loopback exception
			"http://localhost/cb",
			"http://localhost:49152/cb",
		},
		{
			// The loopback exception is limited to http
			"https://127.0.0.1/cb",
			"https://127.0.0.1:49152/cb",
		},
		{
			// Only an actual port difference is relaxed
			"http://127.0.0.1/cb",
			"http://127.0.0.1:/cb",
		},
		{
			// Fragments are not allowed
			"https://app.example.com/cb",
			"https://app.example.com/cb#fragment",
		},
		{
			// Encoded path segments are compared as strings, not decoded
			"https://app.example.com/cb%2Fx",
			"https://app.example.com/cb/x",
		},
		{
			// An empty query is part of the string
			"https://app.example.com/cb?",
			"https://app.example.com/cb",
		},
		{
			// Userinfo is not ignored
			"https://app.example.com/cb",
			"https://user@app.example.com/cb",
		},
	}
	for _, v := range invalid {
		if _, err := validateUriListExact(v[0], v[1], ""); err == nil {
			t.Errorf("Expected validateUriListExact(%s, %s) to fail", v[0], v[1])
		}
	}

	// Registered lists keep the list semantics of ValidateUriList
	if _, err := validateUriListExact("https://one.example.com/cb;https://two.example.com/cb", "https://two.example.com/cb", ";"); err != nil {
		t.Errorf("Expected second list entry to match, got %v", err)
	}
	if _, err := validateUriListExact("https://one.example.com/cb;https://two.example.com/cb", "https://two.example.com/cb/extra", ";"); err == nil {
		t.Error("Expected subpath of second list entry to fail")
	}
}

func TestValidateUriExactList(t *testing.T) {
	registered := []string{"https://one.example.com/cb", "http://127.0.0.1/cb"}

	valid := [][]string{
		{
			"https://one.example.com/cb",
			"https://one.example.com/cb",
		},
		{
			// Any entry may match
			"http://127.0.0.1:49152/cb",
			"http://127.0.0.1:49152/cb",
		},
	}
	for _, v := range valid {
		if realRedirectUri, err := validateUriExactList(registered, v[0]); err != nil {
			t.Errorf("Expected validateUriExactList(%v, %s) to succeed, got %v", registered, v[0], err)
		} else if realRedirectUri != v[1] {
			t.Errorf("Expected validateUriExactList(%v, %s) to return uri %s, got %s", registered, v[0], v[1], realRedirectUri)
		}
	}

	invalid := []string{
		// Not registered
		"https://three.example.com/cb",
		// Subpaths are not accepted
		"https://one.example.com/cb/extra",
		// Query strings are compared as strings
		"https://one.example.com/cb?x=1",
		// The loopback exception does not relax the path
		"http://127.0.0.1:49152/cb/extra",
	}
	for _, v := range invalid {
		if _, err := validateUriExactList(registered, v); err == nil {
			t.Errorf("Expected validateUriExactList(%v, %s) to fail", registered, v)
		}
	}
}

func TestClientRedirectUris(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.RedirectUriSeparator = ";"
	server := NewServer(sconfig, NewTestingStorage())

	// A client that returns a set keeps it as it is, and the set alone decides
	// the matching: the separator and the legacy single value are not used.
	setClient := &DefaultClient{
		Id:           "set-client",
		RedirectUri:  "https://legacy.example.com/cb",
		RedirectUris: []string{"https://one.example.com/cb", "https://two.example.com/cb"},
	}
	registered, validate := server.clientRedirectUris(setClient)
	if len(registered) != 2 || registered[0] != "https://one.example.com/cb" || registered[1] != "https://two.example.com/cb" {
		t.Errorf("Unexpected registered uris: %v", registered)
	}
	if _, err := validate("https://two.example.com/cb"); err != nil {
		t.Errorf("Expected every entry of the set to match, got %v", err)
	}
	if _, err := validate("https://legacy.example.com/cb"); err == nil {
		t.Error("Expected the legacy single value to be ignored when a set is registered")
	}
	if _, err := validate("https://two.example.com/cb/extra"); err == nil {
		t.Error("Expected a subpath of a registered uri to fail")
	}

	// A client without a set falls back to the legacy single value, split by
	// the separator, compared the way EnforceOAuth21 selects.
	legacyClient := &DefaultClient{
		Id:          "legacy-client",
		RedirectUri: "https://one.example.com/cb;https://two.example.com/cb",
	}
	registered, validate = server.clientRedirectUris(legacyClient)
	if len(registered) != 2 || registered[0] != "https://one.example.com/cb" {
		t.Errorf("Unexpected registered uris: %v", registered)
	}
	if _, err := validate("https://two.example.com/cb/extra"); err != nil {
		t.Errorf("Expected a subpath to match while EnforceOAuth21 is off, got %v", err)
	}

	sconfig.EnforceOAuth21 = true
	_, validate = server.clientRedirectUris(legacyClient)
	if _, err := validate("https://two.example.com/cb/extra"); err == nil {
		t.Error("Expected a subpath to fail while EnforceOAuth21 is on")
	}
	if _, err := validate("https://two.example.com/cb"); err != nil {
		t.Errorf("Expected a registered uri to match while EnforceOAuth21 is on, got %v", err)
	}

	// An empty set falls back to the legacy single value as well
	emptySetClient := &DefaultClient{
		Id:           "empty-set-client",
		RedirectUri:  "https://legacy.example.com/cb",
		RedirectUris: []string{},
	}
	registered, validate = server.clientRedirectUris(emptySetClient)
	if len(registered) != 1 || registered[0] != "https://legacy.example.com/cb" {
		t.Errorf("Unexpected registered uris: %v", registered)
	}
	if _, err := validate("https://legacy.example.com/cb"); err != nil {
		t.Errorf("Expected the legacy single value to match, got %v", err)
	}
}

func TestClientHasRedirectUri(t *testing.T) {
	testcases := map[string]struct {
		client   Client
		expected bool
	}{
		"single value": {
			client:   &clientWithoutMatcher{Id: "client", RedirectUri: "https://app.example.com/cb"},
			expected: true,
		},
		"set without a single value": {
			client:   &clientWithRedirectUriSet{Id: "client", RedirectUris: []string{"https://app.example.com/cb"}},
			expected: true,
		},
		"set with a single value": {
			client:   &DefaultClient{Id: "client", RedirectUri: "https://app.example.com/cb", RedirectUris: []string{"https://app.example.com/cb"}},
			expected: true,
		},
		"neither": {
			client:   &DefaultClient{Id: "client"},
			expected: false,
		},
		"empty single value": {
			client:   &clientWithoutMatcher{Id: "client"},
			expected: false,
		},
	}

	for k, tt := range testcases {
		if got := clientHasRedirectUri(tt.client); got != tt.expected {
			t.Errorf("%s: expected %v, got %v", k, tt.expected, got)
		}
	}
}
