package osin

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAccessAuthorizationCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessRefreshToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}
	//fmt.Printf("%+v", resp)

	if _, err := server.Storage.LoadRefresh("r9999"); err == nil {
		t.Fatalf("token was not deleted")
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessRefreshTokenSaveToken(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	server.Config.RetainTokenAfterRefresh = true
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}
	//fmt.Printf("%+v", resp)

	if _, err := server.Storage.LoadRefresh("r9999"); err != nil {
		t.Fatalf("token incorrectly deleted: %s", err.Error())
	}

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessPassword(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "testing")
	req.Form.Set("password", "testing")
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = ar.Username == "testing" && ar.Password == "testing"
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d := resp.Output["refresh_token"]; d != "r1" {
		t.Fatalf("Unexpected refresh token: %s", d)
	}
}

func TestAccessClientCredentials(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}
	resp := server.NewResponse()

	req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("1234", "aabbccdd")

	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.Form.Set("state", "a")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	//fmt.Printf("%+v", resp)

	if resp.IsError && resp.InternalError != nil {
		t.Fatalf("Error in response: %s", resp.InternalError)
	}

	if resp.IsError {
		t.Fatalf("Should not be an error")
	}

	if resp.Type != DATA {
		t.Fatalf("Response should be data")
	}

	if d := resp.Output["access_token"]; d != "1" {
		t.Fatalf("Unexpected access token: %s", d)
	}

	if d, dok := resp.Output["refresh_token"]; dok {
		t.Fatalf("Refresh token should not be generated: %s", d)
	}
}

func TestExtraScopes(t *testing.T) {
	if extraScopes("", "") == true {
		t.Fatalf("extraScopes returned true with empty scopes")
	}

	if extraScopes("a", "") == true {
		t.Fatalf("extraScopes returned true with less scopes")
	}

	if extraScopes("a b", "b a") == true {
		t.Fatalf("extraScopes returned true with matching scopes")
	}

	if extraScopes("a b", "b a c") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

	if extraScopes("", "a") == false {
		t.Fatalf("extraScopes returned false with extra scopes")
	}

}

// clientWithoutMatcher just implements the base Client interface
type clientWithoutMatcher struct {
	Id          string
	Secret      string
	RedirectUri string
}

func (c *clientWithoutMatcher) GetId() string          { return c.Id }
func (c *clientWithoutMatcher) GetSecret() string      { return c.Secret }
func (c *clientWithoutMatcher) GetRedirectUri() string { return c.RedirectUri }
func (c *clientWithoutMatcher) GetUserData() any       { return nil }

func TestGetClientWithoutMatcher(t *testing.T) {
	myclient := &clientWithoutMatcher{
		Id:          "myclient",
		Secret:      "myclientsecret",
		RedirectUri: "http://www.example.com",
	}
	storage := &TestingStorage{clients: map[string]Client{myclient.Id: myclient}}
	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	// Ensure bad secret fails
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "invalidsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}

		if !w.IsError {
			t.Error("No error in response")
		}

		if w.ErrorId != E_UNAUTHORIZED_CLIENT {
			t.Errorf("Expected error %v, got %v", E_UNAUTHORIZED_CLIENT, w.ErrorId)
		}
	}

	// Ensure nonexistent client fails
	{
		auth := &BasicAuth{
			Username: "nonexistent",
			Password: "nonexistent",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}

		if !w.IsError {
			t.Error("No error in response")
		}

		if w.ErrorId != E_UNAUTHORIZED_CLIENT {
			t.Errorf("Expected error %v, got %v", E_UNAUTHORIZED_CLIENT, w.ErrorId)
		}
	}

	// Ensure good secret works
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "myclientsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != myclient {
			t.Errorf("Expected client, got nil with response: %v", w)
		}
	}
}

// clientWithMatcher implements the base Client interface and the ClientSecretMatcher interface
type clientWithMatcher struct {
	Id          string
	Secret      string
	RedirectUri string
}

func (c *clientWithMatcher) GetId() string          { return c.Id }
func (c *clientWithMatcher) GetSecret() string      { panic("called GetSecret") }
func (c *clientWithMatcher) GetRedirectUri() string { return c.RedirectUri }
func (c *clientWithMatcher) GetUserData() any       { return nil }
func (c *clientWithMatcher) ClientSecretMatches(secret string) bool {
	return secret == c.Secret
}

func TestGetClientSecretMatcher(t *testing.T) {
	myclient := &clientWithMatcher{
		Id:          "myclient",
		Secret:      "myclientsecret",
		RedirectUri: "http://www.example.com",
	}
	storage := &TestingStorage{clients: map[string]Client{myclient.Id: myclient}}
	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	// Ensure bad secret fails, but does not panic (doesn't call GetSecret)
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "invalidsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != nil {
			t.Errorf("Expected error, got client: %v", client)
		}
	}

	// Ensure good secret works, but does not panic (doesn't call GetSecret)
	{
		auth := &BasicAuth{
			Username: "myclient",
			Password: "myclientsecret",
		}
		w := &Response{}
		client := server.getClient(auth, storage, w)
		if client != myclient {
			t.Errorf("Expected client, got nil with response: %v", w)
		}
	}
}

func TestAccessAuthorizationCodePKCE(t *testing.T) {
	testcases := map[string]struct {
		Challenge       string
		ChallengeMethod string
		Verifier        string
		ExpectedError   string
	}{
		"good, plain": {
			Challenge: "12345678901234567890123456789012345678901234567890",
			Verifier:  "12345678901234567890123456789012345678901234567890",
		},
		"bad, plain": {
			Challenge:     "12345678901234567890123456789012345678901234567890",
			Verifier:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError: "invalid_grant",
		},
		"good, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"bad, S256": {
			Challenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ChallengeMethod: "S256",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   "invalid_grant",
		},
		"missing from storage": {
			Challenge:       "",
			ChallengeMethod: "",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		sconfig := NewServerConfig()
		sconfig.AllowClientSecretInParams = true
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		server.Storage.SaveAuthorize(&AuthorizeData{
			Client:              testStorage.clients["public-client"],
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectUri:         "http://localhost:14000/appauth",
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: test.ChallengeMethod,
		})
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}

		// req.SetBasicAuth("public-client", "")

		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("client_id", "public-client")
		// Parameter credentials are enabled, so the public client has to send
		// the client_secret parameter; it is allowed to be empty.
		req.Form.Set("client_secret", "")
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		req.Form.Set("code_verifier", test.Verifier)
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			if test.ExpectedError == "" || test.ExpectedError != resp.ErrorId {
				t.Errorf("%s: unexpected error: %v, %v", k, resp.ErrorId, resp.InternalError)
				continue
			}
		}
		if test.ExpectedError == "" {
			if resp.Type != DATA {
				t.Fatalf("%s: Response should be data", k)
			}
			if d := resp.Output["access_token"]; d != "1" {
				t.Fatalf("%s: Unexpected access token: %s", k, d)
			}
			if d := resp.Output["refresh_token"]; d != "r1" {
				t.Fatalf("%s: Unexpected refresh token: %s", k, d)
			}
		}
	}
}

func TestAccessAuthorizationCodeEnforceOAuth21PKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	testcases := map[string]struct {
		Challenge       string
		ChallengeMethod string
		Verifier        string
		ExpectedError   string
	}{
		"good, S256": {
			Challenge:       challenge,
			ChallengeMethod: "S256",
			Verifier:        verifier,
		},
		"good, plain": {
			Challenge: "12345678901234567890123456789012345678901234567890",
			Verifier:  "12345678901234567890123456789012345678901234567890",
		},
		"missing verifier": {
			Challenge:       challenge,
			ChallengeMethod: "S256",
			ExpectedError:   "invalid_grant",
		},
		"bad verifier": {
			Challenge:       challenge,
			ChallengeMethod: "S256",
			Verifier:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			ExpectedError:   "invalid_grant",
		},
		"code without challenge": {
			ExpectedError: "invalid_grant",
		},
		"verifier without challenge": {
			Verifier:      verifier,
			ExpectedError: "invalid_request",
		},
	}

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		sconfig := NewServerConfig()
		sconfig.EnforceOAuth21 = true
		sconfig.AllowClientSecretInParams = false
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		testStorage.SaveAuthorize(&AuthorizeData{
			Client:              testStorage.clients["public-client"],
			Code:                "pkce-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectUri:         "http://localhost:14000/appauth",
			CodeChallenge:       test.Challenge,
			CodeChallengeMethod: test.ChallengeMethod,
		})
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("client_id", "public-client")
		req.Form.Set("code", "pkce-code")
		req.Form.Set("state", "a")
		if test.Verifier != "" {
			req.Form.Set("code_verifier", test.Verifier)
		}
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			if test.ExpectedError == "" || test.ExpectedError != resp.ErrorId {
				t.Errorf("%s: unexpected error: %v, %v", k, resp.ErrorId, resp.InternalError)
				continue
			}
		}
		if test.ExpectedError == "" {
			if resp.Type != DATA {
				t.Fatalf("%s: Response should be data", k)
			}
			if d := resp.Output["access_token"]; d != "1" {
				t.Fatalf("%s: Unexpected access token: %s", k, d)
			}
			if d := resp.Output["refresh_token"]; d != "r1" {
				t.Fatalf("%s: Unexpected refresh token: %s", k, d)
			}
		}
	}
}

func TestAccessAuthorizationCodeEnforceOAuth21ClientAuth(t *testing.T) {
	challenge := "12345678901234567890123456789012345678901234567890"

	testcases := map[string]struct {
		codeClientID  string
		formClientID  string
		formSecret    string
		basicAuth     bool
		basicClientID string
		basicSecret   string
		allowParams   bool
		ExpectedError string
	}{
		"public client with client_id parameter": {
			codeClientID: "public-client",
			formClientID: "public-client",
		},
		"public client with empty basic secret": {
			codeClientID:  "public-client",
			basicAuth:     true,
			basicClientID: "public-client",
			ExpectedError: "invalid_request",
		},
		"secret client with client_id parameter only": {
			codeClientID:  "1234",
			formClientID:  "1234",
			ExpectedError: "invalid_client",
		},
		"secret client with ignored secret parameter": {
			codeClientID:  "1234",
			formClientID:  "1234",
			formSecret:    "aabbccdd",
			ExpectedError: "invalid_client",
		},
		"secret client with basic auth": {
			codeClientID:  "1234",
			basicAuth:     true,
			basicClientID: "1234",
			basicSecret:   "aabbccdd",
		},
		"secret client with allowed parameter credentials": {
			codeClientID: "1234",
			formClientID: "1234",
			formSecret:   "aabbccdd",
			allowParams:  true,
		},
		"no client credentials": {
			codeClientID:  "public-client",
			ExpectedError: "invalid_request",
		},
	}

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		client := testStorage.clients[test.codeClientID]
		testStorage.SaveAuthorize(&AuthorizeData{
			Client:        client,
			Code:          "client-auth-code",
			ExpiresIn:     3600,
			CreatedAt:     time.Now(),
			RedirectUri:   client.GetRedirectUri(),
			CodeChallenge: challenge,
		})

		sconfig := NewServerConfig()
		sconfig.EnforceOAuth21 = true
		sconfig.AllowClientSecretInParams = test.allowParams
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.basicAuth {
			req.SetBasicAuth(test.basicClientID, test.basicSecret)
		}
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "client-auth-code")
		req.Form.Set("code_verifier", challenge)
		if test.formClientID != "" {
			req.Form.Set("client_id", test.formClientID)
		}
		if test.formSecret != "" {
			req.Form.Set("client_secret", test.formSecret)
		}
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if test.ExpectedError != "" {
			if !resp.IsError || resp.ErrorId != test.ExpectedError {
				t.Errorf("%s: expected %s, got %v (%v)", k, test.ExpectedError, resp.ErrorId, resp.InternalError)
			}
			continue
		}
		if resp.IsError {
			t.Errorf("%s: unexpected error: %v (%v)", k, resp.ErrorId, resp.InternalError)
			continue
		}
		if d := resp.Output["access_token"]; d != "1" {
			t.Errorf("%s: Unexpected access token: %s", k, d)
		}
	}
}

func TestAccessAuthorizationCodeEnforceOAuth21RedirectUri(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	registered := "http://localhost:14000/appauth;http://localhost:14000/other"

	testcases := map[string]struct {
		RedirectUri   string
		ExpectedError string
	}{
		"matches the authorization request": {RedirectUri: "http://localhost:14000/appauth"},
		"differs from the authorization request": {
			RedirectUri:   "http://localhost:14000/other",
			ExpectedError: "invalid_request",
		},
		"omitted falls back to the registered uri": {},
	}

	for k, test := range testcases {
		testStorage := NewTestingStorage()
		if err := testStorage.SetClient("client", &DefaultClient{
			Id:          "client",
			Secret:      "secret",
			RedirectUri: registered,
		}); err != nil {
			t.Fatal(err)
		}
		testStorage.SaveAuthorize(&AuthorizeData{
			Client:              testStorage.clients["client"],
			Code:                "redirect-code",
			ExpiresIn:           3600,
			CreatedAt:           time.Now(),
			RedirectUri:         "http://localhost:14000/appauth",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		})

		sconfig := NewServerConfig()
		sconfig.EnforceOAuth21 = true
		sconfig.RedirectUriSeparator = ";"
		sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
		server := NewServer(sconfig, testStorage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("client", "secret")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "redirect-code")
		req.Form.Set("code_verifier", verifier)
		if test.RedirectUri != "" {
			req.Form.Set("redirect_uri", test.RedirectUri)
		}
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if test.ExpectedError != "" {
			if !resp.IsError || resp.ErrorId != test.ExpectedError {
				t.Errorf("%s: expected %s, got %v (%v)", k, test.ExpectedError, resp.ErrorId, resp.InternalError)
			}
			continue
		}
		if resp.IsError {
			t.Errorf("%s: unexpected error: %v (%v)", k, resp.ErrorId, resp.InternalError)
			continue
		}
		if d := resp.Output["access_token"]; d != "1" {
			t.Errorf("%s: Unexpected access token: %s", k, d)
		}
	}
}

func TestEnforceOAuth21AuthorizationCodeFlow(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	redirectUri := "http://localhost:14000/appauth"

	testcases := map[string]struct {
		clientID  string
		secret    string
		basicAuth bool
	}{
		"client without a secret": {
			clientID: "public-client",
		},
		"client with a secret": {
			clientID:  "1234",
			secret:    "aabbccdd",
			basicAuth: true,
		},
	}

	for k, test := range testcases {
		t.Run(k, func(t *testing.T) {
			sconfig := NewServerConfig()
			sconfig.EnforceOAuth21 = true
			sconfig.AllowClientSecretInParams = false
			sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
			sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
			server := NewServer(sconfig, NewTestingStorage())
			server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
			server.AccessTokenGen = &TestingAccessTokenGen{}

			authResp := server.NewResponse()
			authReq, err := http.NewRequest("GET", redirectUri, nil)
			if err != nil {
				t.Fatal(err)
			}
			authReq.Form = make(url.Values)
			authReq.Form.Set("response_type", string(CODE))
			authReq.Form.Set("client_id", test.clientID)
			authReq.Form.Set("redirect_uri", redirectUri)
			authReq.Form.Set("state", "a")
			authReq.Form.Set("code_challenge", challenge)
			authReq.Form.Set("code_challenge_method", "S256")

			if ar := server.HandleAuthorizeRequest(authResp, authReq); ar != nil {
				ar.Authorized = true
				server.FinishAuthorizeRequest(authResp, authReq, ar)
			}
			if authResp.IsError {
				t.Fatalf("Authorization error: %v (%v)", authResp.ErrorId, authResp.InternalError)
			}
			code, ok := authResp.Output["code"].(string)
			if !ok {
				t.Fatalf("No authorization code issued: %#v", authResp.Output)
			}

			tokenResp := server.NewResponse()
			tokenReq, err := http.NewRequest("POST", redirectUri, nil)
			if err != nil {
				t.Fatal(err)
			}
			tokenReq.Form = make(url.Values)
			if test.basicAuth {
				tokenReq.SetBasicAuth(test.clientID, test.secret)
			} else {
				// Clients without a secret identify themselves with the client_id parameter alone
				tokenReq.Form.Set("client_id", test.clientID)
			}
			tokenReq.Form.Set("grant_type", string(AUTHORIZATION_CODE))
			tokenReq.Form.Set("redirect_uri", redirectUri)
			tokenReq.Form.Set("code", code)
			tokenReq.Form.Set("code_verifier", verifier)
			tokenReq.PostForm = make(url.Values)

			if ar := server.HandleAccessRequest(tokenResp, tokenReq); ar != nil {
				ar.Authorized = true
				server.FinishAccessRequest(tokenResp, tokenReq, ar)
			}
			if tokenResp.IsError {
				t.Fatalf("Token error: %v (%v)", tokenResp.ErrorId, tokenResp.InternalError)
			}
			if d := tokenResp.Output["access_token"]; d != "1" {
				t.Fatalf("Unexpected access token: %s", d)
			}
			if d := tokenResp.Output["refresh_token"]; d != "r1" {
				t.Fatalf("Unexpected refresh token: %s", d)
			}
		})
	}
}

// senderConstraintStorage is a TestingStorage that declares it persists sender
// constraints.
type senderConstraintStorage struct {
	*TestingStorage
}

func (s *senderConstraintStorage) Clone() Storage {
	return s
}

func (s *senderConstraintStorage) SupportsSenderConstraints() bool {
	return true
}

func TestAccessClientAuthMethod(t *testing.T) {
	redirectUri := "http://localhost:14000/appauth"

	testcases := map[string]struct {
		client         Client
		enforceOAuth21 bool
		allowParams    bool
		basicAuth      bool
		clientID       string
		secret         string
		secretParam    bool
		expectError    string
	}{
		"none client holding a secret identifies with client_id alone": {
			client:   &DefaultClient{Id: "none-client", Secret: "aabbccdd", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_NONE},
			clientID: "none-client",
		},
		"none client identifies with client_id alone when parameter credentials are enabled": {
			client:      &DefaultClient{Id: "none-client", Secret: "aabbccdd", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_NONE},
			allowParams: true,
			clientID:    "none-client",
		},
		"shared secret client with basic auth": {
			client:    &DefaultClient{Id: "basic-client", Secret: "aabbccdd", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_CLIENT_SECRET_BASIC},
			basicAuth: true,
			clientID:  "basic-client",
			secret:    "aabbccdd",
		},
		"shared secret client with client_id alone": {
			client:      &DefaultClient{Id: "basic-client", Secret: "aabbccdd", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_CLIENT_SECRET_BASIC},
			clientID:    "basic-client",
			expectError: E_INVALID_REQUEST,
		},
		"private_key_jwt client with client_id alone": {
			client:         &DefaultClient{Id: "jwt-client", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_PRIVATE_KEY_JWT},
			enforceOAuth21: true,
			clientID:       "jwt-client",
			expectError:    E_INVALID_CLIENT,
		},
		"private_key_jwt client with a shared secret": {
			client:         &DefaultClient{Id: "jwt-client", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_PRIVATE_KEY_JWT},
			enforceOAuth21: true,
			allowParams:    true,
			clientID:       "jwt-client",
			secret:         "aabbccdd",
			expectError:    E_UNAUTHORIZED_CLIENT,
		},
		"client without a declared method and no secret": {
			client:      &clientWithoutMatcher{Id: "legacy-public", RedirectUri: redirectUri},
			allowParams: true,
			clientID:    "legacy-public",
			secretParam: true,
		},
		"client without a declared method holding a secret": {
			client:      &clientWithoutMatcher{Id: "legacy-secret", Secret: "aabbccdd", RedirectUri: redirectUri},
			clientID:    "legacy-secret",
			expectError: E_INVALID_REQUEST,
		},
		"no client credentials": {
			client:      &DefaultClient{Id: "none-client", Secret: "aabbccdd", RedirectUri: redirectUri, AuthMethod: AUTH_METHOD_NONE},
			expectError: E_INVALID_REQUEST,
		},
	}

	for k, tt := range testcases {
		t.Run(k, func(t *testing.T) {
			storage := NewTestingStorage()
			if err := storage.SetClient(tt.client.GetId(), tt.client); err != nil {
				t.Fatal(err)
			}
			sconfig := NewServerConfig()
			sconfig.EnforceOAuth21 = tt.enforceOAuth21
			sconfig.AllowClientSecretInParams = tt.allowParams
			sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
			server := NewServer(sconfig, storage)
			server.AccessTokenGen = &TestingAccessTokenGen{}
			resp := server.NewResponse()

			req, err := http.NewRequest("POST", redirectUri, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.basicAuth {
				req.SetBasicAuth(tt.clientID, tt.secret)
			}
			req.Form = make(url.Values)
			req.Form.Set("grant_type", string(PASSWORD))
			req.Form.Set("username", "testing")
			req.Form.Set("password", "testing")
			if tt.clientID != "" {
				req.Form.Set("client_id", tt.clientID)
			}
			if tt.secretParam || tt.secret != "" {
				req.Form.Set("client_secret", tt.secret)
			}
			req.PostForm = make(url.Values)

			if ar := server.HandleAccessRequest(resp, req); ar != nil {
				ar.Authorized = true
				server.FinishAccessRequest(resp, req, ar)
			}

			if tt.expectError != "" {
				if !resp.IsError || resp.ErrorId != tt.expectError {
					t.Fatalf("Expected %s, got %v (%v)", tt.expectError, resp.ErrorId, resp.InternalError)
				}
				if _, ok := resp.Output["access_token"]; ok {
					t.Error("No access token should be issued")
				}
				return
			}

			if resp.IsError {
				t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
			}
			if d := resp.Output["access_token"]; d != "1" {
				t.Fatalf("Unexpected access token: %s", d)
			}
		})
	}
}

func TestAccessRedirectUriSet(t *testing.T) {
	first := "https://app.example.com/cb"
	second := "https://other.example.com/cb"
	setClient := &DefaultClient{
		Id:           "set-client",
		RedirectUris: []string{first, second},
		AuthMethod:   AUTH_METHOD_NONE,
	}

	testcases := map[string]struct {
		grantType   AccessRequestType
		redirectUri string
		seed        func(*testing.T, *TestingStorage)
		expectedUri string
	}{
		"authorization code": {
			grantType:   AUTHORIZATION_CODE,
			redirectUri: second,
			seed: func(t *testing.T, storage *TestingStorage) {
				if err := storage.SaveAuthorize(&AuthorizeData{
					Client:      setClient,
					Code:        "set-code",
					ExpiresIn:   3600,
					CreatedAt:   time.Now(),
					RedirectUri: second,
				}); err != nil {
					t.Fatal(err)
				}
			},
			expectedUri: second,
		},
		"refresh token": {
			grantType: REFRESH_TOKEN,
			seed: func(t *testing.T, storage *TestingStorage) {
				if err := storage.SaveAccess(&AccessData{
					Client:       setClient,
					AccessToken:  "set-access",
					RefreshToken: "set-refresh",
					ExpiresIn:    3600,
					CreatedAt:    time.Now(),
					RedirectUri:  second,
				}); err != nil {
					t.Fatal(err)
				}
			},
			expectedUri: second,
		},
		"password": {
			grantType:   PASSWORD,
			expectedUri: first,
		},
		"client credentials": {
			grantType:   CLIENT_CREDENTIALS,
			expectedUri: first,
		},
		"assertion": {
			grantType:   ASSERTION,
			expectedUri: first,
		},
	}

	for k, tt := range testcases {
		t.Run(k, func(t *testing.T) {
			storage := NewTestingStorage()
			if err := storage.SetClient(setClient.Id, setClient); err != nil {
				t.Fatal(err)
			}
			if tt.seed != nil {
				tt.seed(t, storage)
			}

			sconfig := NewServerConfig()
			sconfig.RedirectUriSeparator = ";"
			sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE, REFRESH_TOKEN, PASSWORD, CLIENT_CREDENTIALS, ASSERTION}
			server := NewServer(sconfig, storage)
			server.AccessTokenGen = &TestingAccessTokenGen{}
			resp := server.NewResponse()

			req, err := http.NewRequest("POST", first, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Form = make(url.Values)
			req.Form.Set("grant_type", string(tt.grantType))
			req.Form.Set("client_id", setClient.Id)
			if tt.redirectUri != "" {
				req.Form.Set("redirect_uri", tt.redirectUri)
			}
			switch tt.grantType {
			case AUTHORIZATION_CODE:
				req.Form.Set("code", "set-code")
			case REFRESH_TOKEN:
				req.Form.Set("refresh_token", "set-refresh")
			case PASSWORD:
				req.Form.Set("username", "testing")
				req.Form.Set("password", "testing")
			case ASSERTION:
				req.Form.Set("assertion_type", "testing")
				req.Form.Set("assertion", "testing")
			}
			req.PostForm = make(url.Values)

			ar := server.HandleAccessRequest(resp, req)
			if ar == nil {
				t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
			}
			if ar.RedirectUri != tt.expectedUri {
				t.Errorf("Expected redirect uri %s, got %s", tt.expectedUri, ar.RedirectUri)
			}

			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
			if resp.IsError {
				t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
			}
			if d := resp.Output["access_token"]; d != "1" {
				t.Errorf("Unexpected access token: %s", d)
			}
		})
	}
}

func TestAccessSenderConstrainedTokens(t *testing.T) {
	// A deployment that requires sender constrained tokens does not issue
	// tokens through a storage that cannot persist the binding.
	t.Run("storage without the capability", func(t *testing.T) {
		sconfig := NewServerConfig()
		sconfig.RequireSenderConstrainedTokens = true
		sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
		storage := NewTestingStorage()
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if !resp.IsError || resp.ErrorId != E_SERVER_ERROR {
			t.Fatalf("Expected %s, got %v (%v)", E_SERVER_ERROR, resp.ErrorId, resp.InternalError)
		}
		if _, ok := resp.Output["access_token"]; ok {
			t.Error("No access token should be issued")
		}
		if _, err := storage.LoadAccess("1"); err == nil {
			t.Error("No access token should be saved")
		}
	})

	// A refresh token that lost its binding is rejected while the policy is
	// on, and no new token is issued.
	t.Run("unbound refresh token", func(t *testing.T) {
		storage := &senderConstraintStorage{TestingStorage: NewTestingStorage()}
		if err := storage.SaveAccess(&AccessData{
			Client:       storage.clients["1234"],
			AccessToken:  "unbound-access",
			RefreshToken: "unbound-refresh",
			ExpiresIn:    3600,
			CreatedAt:    time.Now(),
			RedirectUri:  "http://localhost:14000/appauth",
		}); err != nil {
			t.Fatal(err)
		}

		sconfig := NewServerConfig()
		sconfig.RequireSenderConstrainedTokens = true
		sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(REFRESH_TOKEN))
		req.Form.Set("refresh_token", "unbound-refresh")
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if !resp.IsError || resp.ErrorId != E_INVALID_GRANT {
			t.Fatalf("Expected %s, got %v (%v)", E_INVALID_GRANT, resp.ErrorId, resp.InternalError)
		}
		if _, ok := resp.Output["access_token"]; ok {
			t.Error("No access token should be issued")
		}
		if _, err := storage.LoadRefresh("unbound-refresh"); err != nil {
			t.Errorf("The rejected refresh token should not be consumed: %s", err)
		}
	})

	// A refresh token that carries a binding is exchanged as usual.
	t.Run("bound refresh token", func(t *testing.T) {
		storage := &senderConstraintStorage{TestingStorage: NewTestingStorage()}
		if err := storage.SaveAccess(&AccessData{
			Client:           storage.clients["1234"],
			AccessToken:      "bound-access",
			RefreshToken:     "bound-refresh",
			ExpiresIn:        3600,
			CreatedAt:        time.Now(),
			RedirectUri:      "http://localhost:14000/appauth",
			SenderConstraint: "jkt-1",
		}); err != nil {
			t.Fatal(err)
		}

		sconfig := NewServerConfig()
		sconfig.RequireSenderConstrainedTokens = true
		sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(REFRESH_TOKEN))
		req.Form.Set("refresh_token", "bound-refresh")
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
		}
		if d := resp.Output["access_token"]; d != "1" {
			t.Fatalf("Unexpected access token: %s", d)
		}
		replacement, err := storage.LoadAccess("1")
		if err != nil {
			t.Fatalf("The replacement access token should be saved: %s", err)
		}
		if replacement.SenderConstraint != "jkt-1" {
			t.Errorf("The replacement token should keep the binding, got %q", replacement.SenderConstraint)
		}
	})

	// The policy is off by default: an unbound token is exchanged as before.
	t.Run("policy off", func(t *testing.T) {
		storage := NewTestingStorage()
		sconfig := NewServerConfig()
		sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(REFRESH_TOKEN))
		req.Form.Set("refresh_token", "r9999")
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
		}
		if d := resp.Output["access_token"]; d != "1" {
			t.Fatalf("Unexpected access token: %s", d)
		}
	})

	// A capable storage is not enough: a token that would arrive at the client
	// unbound is refused at issuance, not at its first use.
	t.Run("capable storage without a binding", func(t *testing.T) {
		storage := &senderConstraintStorage{TestingStorage: NewTestingStorage()}
		sconfig := NewServerConfig()
		sconfig.RequireSenderConstrainedTokens = true
		sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, req, ar)
		}

		if !resp.IsError || resp.ErrorId != E_SERVER_ERROR {
			t.Fatalf("Expected %s, got %v (%v)", E_SERVER_ERROR, resp.ErrorId, resp.InternalError)
		}
		if _, ok := resp.Output["access_token"]; ok {
			t.Error("No access token should be issued")
		}
		if _, err := storage.LoadAccess("1"); err == nil {
			t.Error("No access token should be saved")
		}
	})

	// An access request that carries the binding is issued as usual.
	t.Run("capable storage with a binding", func(t *testing.T) {
		storage := &senderConstraintStorage{TestingStorage: NewTestingStorage()}
		sconfig := NewServerConfig()
		sconfig.RequireSenderConstrainedTokens = true
		sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
		server := NewServer(sconfig, storage)
		server.AccessTokenGen = &TestingAccessTokenGen{}
		resp := server.NewResponse()

		req, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
		req.PostForm = make(url.Values)

		if ar := server.HandleAccessRequest(resp, req); ar != nil {
			ar.Authorized = true
			ar.ForceAccessData = &AccessData{
				Client:           ar.Client,
				AccessToken:      "bound-access",
				ExpiresIn:        3600,
				CreatedAt:        server.Now(),
				RedirectUri:      "http://localhost:14000/appauth",
				SenderConstraint: "jkt-1",
			}
			server.FinishAccessRequest(resp, req, ar)
		}

		if resp.IsError {
			t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
		}
		if d := resp.Output["access_token"]; d != "bound-access" {
			t.Fatalf("Unexpected access token: %s", d)
		}
		saved, err := storage.LoadAccess("bound-access")
		if err != nil {
			t.Fatalf("The bound access token should be saved: %s", err)
		}
		if saved.SenderConstraint != "jkt-1" {
			t.Errorf("Unexpected sender constraint: %s", saved.SenderConstraint)
		}
	})
}
