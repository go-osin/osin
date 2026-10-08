package osin

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestInfo(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("code", "9999")

	if ar := server.HandleInfoRequest(resp, req); ar != nil {
		server.FinishInfoRequest(resp, req, ar)
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

	if d := resp.Output["access_token"]; d != "9999" {
		t.Fatalf("Unexpected authorization code: %s", d)
	}
}

func TestInfoWhenCodeIsOnHeader(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())
	resp := server.NewResponse()

	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer 9999")

	if ar := server.HandleInfoRequest(resp, req); ar != nil {
		server.FinishInfoRequest(resp, req, ar)
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

	if d := resp.Output["access_token"]; d != "9999" {
		t.Fatalf("Unexpected authorization code: %s", d)
	}
}

func TestInfoSenderConstrainedTokens(t *testing.T) {
	testcases := map[string]struct {
		require       bool
		senderBinding string
		token         string
		expectError   string
	}{
		"policy on with an unbound token": {
			require:     true,
			token:       "9999",
			expectError: E_INVALID_GRANT,
		},
		"policy on with a bound token": {
			require:       true,
			senderBinding: "jkt-1",
			token:         "bound",
		},
		"policy off with an unbound token": {
			token: "9999",
		},
	}

	for k, tt := range testcases {
		t.Run(k, func(t *testing.T) {
			storage := NewTestingStorage()
			if tt.senderBinding != "" {
				if err := storage.SaveAccess(&AccessData{
					Client:           storage.clients["1234"],
					AccessToken:      tt.token,
					ExpiresIn:        3600,
					CreatedAt:        time.Now(),
					RedirectUri:      "http://localhost:14000/appauth",
					SenderConstraint: tt.senderBinding,
				}); err != nil {
					t.Fatal(err)
				}
			}

			sconfig := NewServerConfig()
			sconfig.RequireSenderConstrainedTokens = tt.require
			server := NewServer(sconfig, storage)
			resp := server.NewResponse()

			req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Form = make(url.Values)
			req.Form.Set("code", tt.token)

			if ar := server.HandleInfoRequest(resp, req); ar != nil {
				server.FinishInfoRequest(resp, req, ar)
			}

			if tt.expectError != "" {
				if !resp.IsError || resp.ErrorId != tt.expectError {
					t.Fatalf("Expected %s, got %v (%v)", tt.expectError, resp.ErrorId, resp.InternalError)
				}
				if _, ok := resp.Output["access_token"]; ok {
					t.Error("No access token should be returned")
				}
				return
			}

			if resp.IsError {
				t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
			}
			if d := resp.Output["access_token"]; d != tt.token {
				t.Fatalf("Unexpected access token: %s", d)
			}
		})
	}
}

// The remaining lifetime is measured with the server clock, so an injected
// Server.Now must be the only thing that decides it.
func TestInfoExpiresInUsesServerNow(t *testing.T) {
	storage := NewTestingStorage()
	server := NewServer(NewServerConfig(), storage)

	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	server.Now = func() time.Time { return now }

	if err := storage.SaveAccess(&AccessData{
		Client:      storage.clients["1234"],
		AccessToken: "server-clock",
		ExpiresIn:   3600,
		CreatedAt:   now.Add(-30 * time.Minute),
		RedirectUri: "http://localhost:14000/appauth",
	}); err != nil {
		t.Fatal(err)
	}

	resp := server.NewResponse()
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("code", "server-clock")

	if ir := server.HandleInfoRequest(resp, req); ir != nil {
		server.FinishInfoRequest(resp, req, ir)
	}

	if resp.IsError {
		t.Fatalf("Unexpected error: %v (%v)", resp.ErrorId, resp.InternalError)
	}
	if d := resp.Output["expires_in"]; d != 30*time.Minute/time.Second {
		t.Fatalf("Expected 1800 seconds of remaining lifetime, got %v", d)
	}
}
