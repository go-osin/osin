package osin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != REDIRECT {
		t.Fatalf("Response should be a redirect")
	}

	if d := resp.Output["code"]; d != "1" {
		t.Fatalf("Unexpected authorization code: %s", d)
	}
}

func TestAuthorizeToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(TOKEN))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != REDIRECT || !resp.RedirectInFragment {
		t.Fatalf("Response should be a redirect with fragment")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}
}

func TestAuthorizeTokenWithInvalidClient(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()
	redirectUri := "http://redirecturi.com"

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(TOKEN))
	req.Form.Set("client_id", "invalidclient")
	req.Form.Set("state", "a")
	req.Form.Set("redirect_uri", redirectUri)

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatalf("Response should be an error")
	}

	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Incorrect error in response: %v", resp.ErrorId)
	}

	usedRedirectUrl, redirectErr := resp.GetRedirectUrl()

	if redirectErr == nil && usedRedirectUrl == redirectUri {
		t.Fatalf("Response must not redirect to the provided redirect URL for an invalid client")
	}
}

func TestAuthorizeCodePKCERequired(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.RequirePKCEForPublicClients = true
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	// Public client returns an error
	{
		resp := server.NewResponse()
		req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("state", "a")
		req.Form.Set("client_id", "public-client")
		if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, req, ar)
		}
		if !resp.IsError || resp.ErrorId != "invalid_request" || strings.Contains(resp.StatusText, "code_challenge") {
			t.Errorf("Expected invalid_request error describing the code_challenge required, got %#v", resp)
		}
	}

	// Confidential client works without PKCE
	{
		resp := server.NewResponse()
		req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("state", "a")
		req.Form.Set("client_id", "1234")
		if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, req, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			t.Fatalf("Error in response: %s", resp.InternalError)
		}
		if resp.IsError {
			t.Fatalf("Should not be an error")
		}
		if resp.Type != REDIRECT {
			t.Fatalf("Response should be a redirect")
		}
		if d := resp.Output["code"]; d != "1" {
			t.Fatalf("Unexpected authorization code: %s", d)
		}
	}
}

func TestAuthorizeCodePKCEPlain(t *testing.T) {
	challenge := "12345678901234567890123456789012345678901234567890"

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != REDIRECT {
		t.Fatalf("Response should be a redirect")
	}

	code, ok := resp.Output["code"].(string)
	if !ok || code != "1" {
		t.Fatalf("Unexpected authorization code: %s", code)
	}

	token, err := server.Storage.LoadAuthorize(code)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if token.CodeChallenge != challenge {
		t.Errorf("Expected stored code_challenge %s, got %s", challenge, token.CodeChallenge)
	}
	if token.CodeChallengeMethod != "plain" {
		t.Errorf("Expected stored code_challenge plain, got %s", token.CodeChallengeMethod)
	}
}

func TestAuthorizeCodePKCES256(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)
	req.Form.Set("code_challenge_method", "S256")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != REDIRECT {
		t.Fatalf("Response should be a redirect")
	}

	code, ok := resp.Output["code"].(string)
	if !ok || code != "1" {
		t.Fatalf("Unexpected authorization code: %s", code)
	}

	token, err := server.Storage.LoadAuthorize(code)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if token.CodeChallenge != challenge {
		t.Errorf("Expected stored code_challenge %s, got %s", challenge, token.CodeChallenge)
	}
	if token.CodeChallengeMethod != "S256" {
		t.Errorf("Expected stored code_challenge S256, got %s", token.CodeChallengeMethod)
	}
}

func TestAuthorizeCodeEnforceOAuth21RequiresPKCE(t *testing.T) {
	// The requirement applies to clients with and without a secret.
	for _, clientID := range []string{"1234", "public-client"} {
		sconfig := NewServerConfig()
		sconfig.EnforceOAuth21 = true
		sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
		server := NewServer(sconfig, NewTestingStorage())
		server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Form = make(url.Values)
		req.Form.Set("response_type", string(CODE))
		req.Form.Set("client_id", clientID)
		req.Form.Set("state", "a")

		if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
			t.Errorf("%s: authorization request without code_challenge should be rejected", clientID)
		}
		if !resp.IsError || resp.ErrorId != E_INVALID_REQUEST {
			t.Errorf("%s: expected %s, got %v (%v)", clientID, E_INVALID_REQUEST, resp.ErrorId, resp.InternalError)
		}
		if _, ok := resp.Output["code"]; ok {
			t.Errorf("%s: no authorization code should be issued", clientID)
		}
	}
}

func TestAuthorizeCodeEnforceOAuth21StoresPKCEState(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	sconfig := NewServerConfig()
	sconfig.EnforceOAuth21 = true
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "public-client")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", challenge)
	req.Form.Set("code_challenge_method", "S256")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
	}

	code, ok := resp.Output["code"].(string)
	if !ok || code != "1" {
		t.Fatalf("Unexpected authorization code: %v", resp.Output["code"])
	}

	token, err := server.Storage.LoadAuthorize(code)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	if token.CodeChallenge != challenge {
		t.Errorf("Expected stored code_challenge %s, got %s", challenge, token.CodeChallenge)
	}
	if token.CodeChallengeMethod != "S256" {
		t.Errorf("Expected stored code_challenge_method S256, got %s", token.CodeChallengeMethod)
	}
}

func TestAuthorizeCodeEnforceOAuth21RedirectUri(t *testing.T) {
	challenge := "12345678901234567890123456789012345678901234567890"

	var tests = []struct {
		name          string
		registeredUri string
		requestedUri  string
		expectError   bool
	}{
		{"exact match", "https://app.example.com/cb", "https://app.example.com/cb", false},
		{"subpath", "https://app.example.com/cb", "https://app.example.com/cb/extra", true},
		{"other subpath", "https://app.example.com/cb", "https://app.example.com/other/cb", true},
		{"query added", "https://app.example.com/cb", "https://app.example.com/cb?x=1", true},
		{"query changed", "https://app.example.com/cb?x=1", "https://app.example.com/cb?x=2", true},
		{"port changed", "https://app.example.com/cb", "https://app.example.com:8443/cb", true},
		{"loopback port changed", "http://127.0.0.1/cb", "http://127.0.0.1:49152/cb", false},
		{"loopback subpath", "http://127.0.0.1/cb", "http://127.0.0.1:49152/cb/extra", true},
		{"localhost port changed", "http://localhost/cb", "http://localhost:49152/cb", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := NewTestingStorage()
			if err := storage.SetClient("client", &DefaultClient{Id: "client", Secret: "secret", RedirectUri: tt.registeredUri}); err != nil {
				t.Fatal(err)
			}

			sconfig := NewServerConfig()
			sconfig.EnforceOAuth21 = true
			sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
			server := NewServer(sconfig, storage)
			server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
			resp := server.NewResponse()

			req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Form = make(url.Values)
			req.Form.Set("response_type", string(CODE))
			req.Form.Set("client_id", "client")
			req.Form.Set("state", "a")
			req.Form.Set("redirect_uri", tt.requestedUri)
			req.Form.Set("code_challenge", challenge)

			if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
				ar.Authorized = true
				server.FinishAuthorizeRequest(resp, req, ar)
			}

			if tt.expectError {
				if !resp.IsError || resp.ErrorId != E_INVALID_REQUEST {
					t.Fatalf("Expected %s, got %v (%v)", E_INVALID_REQUEST, resp.ErrorId, resp.InternalError)
				}
				if resp.Type == REDIRECT {
					t.Fatalf("Response must not redirect to the unregistered uri %s", resp.URL)
				}
				return
			}

			if resp.IsError {
				t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
			}
			if resp.Type != REDIRECT || resp.URL != tt.requestedUri {
				t.Fatalf("Expected redirect to %s, got %s (type %v)", tt.requestedUri, resp.URL, resp.Type)
			}
		})
	}
}

func TestAuthorizeCodeEnforceOAuth21RejectsInvalidPKCE(t *testing.T) {
	var tests = []struct {
		name            string
		challenge       string
		challengeMethod string
	}{
		{"unsupported code_challenge_method", "12345678901234567890123456789012345678901234567890", "S512"},
		{"malformed code_challenge", "short", ""},
		{"code_challenge with invalid characters", "####################", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sconfig := NewServerConfig()
			sconfig.EnforceOAuth21 = true
			sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
			server := NewServer(sconfig, NewTestingStorage())
			server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
			resp := server.NewResponse()

			req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Form = make(url.Values)
			req.Form.Set("response_type", string(CODE))
			req.Form.Set("client_id", "1234")
			req.Form.Set("state", "a")
			req.Form.Set("code_challenge", tt.challenge)
			if tt.challengeMethod != "" {
				req.Form.Set("code_challenge_method", tt.challengeMethod)
			}

			if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
				t.Error("Authorization request with an invalid code_challenge should be rejected")
			}
			if !resp.IsError || resp.ErrorId != E_INVALID_REQUEST {
				t.Fatalf("Expected %s, got %v (%v)", E_INVALID_REQUEST, resp.ErrorId, resp.InternalError)
			}
			if _, ok := resp.Output["code"]; ok {
				t.Error("No authorization code should be issued")
			}
		})
	}
}
