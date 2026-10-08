package osin

import (
	"testing"
)

// DefaultClient carries every optional client capability the library probes for.
var (
	_ Client               = (*DefaultClient)(nil)
	_ ClientSecretMatcher  = (*DefaultClient)(nil)
	_ ClientRedirectUriSet = (*DefaultClient)(nil)
	_ ClientAuthMethod     = (*DefaultClient)(nil)
)

// clientWithRedirectUriSet only implements the base Client interface and the
// redirect uri set interface.
type clientWithRedirectUriSet struct {
	Id           string
	RedirectUris []string
}

func (c *clientWithRedirectUriSet) GetId() string          { return c.Id }
func (c *clientWithRedirectUriSet) GetSecret() string      { return "" }
func (c *clientWithRedirectUriSet) GetRedirectUri() string { return "" }
func (c *clientWithRedirectUriSet) GetUserData() any       { return nil }
func (c *clientWithRedirectUriSet) GetRedirectUris() []string {
	return c.RedirectUris
}

func TestClientIntfUserData(t *testing.T) {
	c := &DefaultClient{
		UserData: make(map[string]any),
	}

	// check if the any returned from the method is a reference
	c.GetUserData().(map[string]any)["test"] = "none"

	if _, ok := c.GetUserData().(map[string]any)["test"]; !ok {
		t.Error("Returned interface is not a reference")
	}
}

func TestClientOptionalInterfaces(t *testing.T) {
	// A client may implement one of the optional interfaces without the other
	uriClient := &clientWithRedirectUriSet{
		Id:           "uri-client",
		RedirectUris: []string{"https://app.example.com/cb"},
	}
	if _, ok := any(uriClient).(ClientRedirectUriSet); !ok {
		t.Error("Expected the client to implement ClientRedirectUriSet")
	}
	if _, ok := any(uriClient).(ClientAuthMethod); ok {
		t.Error("Expected the client not to implement ClientAuthMethod")
	}

	// The optional interfaces never cover the required ones
	var client Client = &DefaultClient{Id: "default"}
	if _, ok := client.(ClientRedirectUriSet); !ok {
		t.Error("Expected DefaultClient to implement ClientRedirectUriSet")
	}
	if _, ok := client.(ClientAuthMethod); !ok {
		t.Error("Expected DefaultClient to implement ClientAuthMethod")
	}
}

func TestClientCopyFromOptionalFacts(t *testing.T) {
	source := &DefaultClient{
		Id:           "source",
		Secret:       "aabbccdd",
		RedirectUri:  "https://legacy.example.com/cb",
		RedirectUris: []string{"https://one.example.com/cb", "https://two.example.com/cb"},
		AuthMethod:   AUTH_METHOD_NONE,
	}

	target := &DefaultClient{}
	target.CopyFrom(source)
	if len(target.RedirectUris) != 2 || target.RedirectUris[0] != "https://one.example.com/cb" || target.RedirectUris[1] != "https://two.example.com/cb" {
		t.Errorf("Unexpected redirect uris: %v", target.RedirectUris)
	}
	if target.GetAuthMethod() != AUTH_METHOD_NONE {
		t.Errorf("Unexpected auth method: %s", target.GetAuthMethod())
	}

	// a client that declares neither fact leaves the target at its zero value
	target.CopyFrom(&clientWithoutMatcher{Id: "plain", Secret: "secret", RedirectUri: "https://legacy.example.com/cb"})
	if target.RedirectUris != nil {
		t.Errorf("Unexpected redirect uris: %v", target.RedirectUris)
	}
	if target.GetAuthMethod() != "" {
		t.Errorf("Unexpected auth method: %s", target.GetAuthMethod())
	}
}
