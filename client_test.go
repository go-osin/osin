package osin

import (
	"testing"
)

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
