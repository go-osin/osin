package osin

import "testing"

func TestNewServerConfigDefaults(t *testing.T) {
	config := NewServerConfig()

	if config.Issuer != "" {
		t.Errorf("Expected no issuer by default, got %s", config.Issuer)
	}
	if config.RejectPlainPKCE {
		t.Error("Expected RejectPlainPKCE to be disabled by default")
	}
	if config.RequireSenderConstrainedTokens {
		t.Error("Expected RequireSenderConstrainedTokens to be disabled by default")
	}
}

func TestServerConfigPolicyFields(t *testing.T) {
	config := NewServerConfig()
	config.Issuer = "https://auth.example.com"
	config.RejectPlainPKCE = true
	config.RequireSenderConstrainedTokens = true

	if config.Issuer != "https://auth.example.com" {
		t.Errorf("Unexpected issuer: %s", config.Issuer)
	}
	if !config.RejectPlainPKCE {
		t.Error("Expected RejectPlainPKCE to be retained")
	}
	if !config.RequireSenderConstrainedTokens {
		t.Error("Expected RequireSenderConstrainedTokens to be retained")
	}
}
