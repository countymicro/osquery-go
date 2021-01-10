package config

import (
	"context"
	"errors"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

var StatusOK = osquery.ExtensionStatus{Code: 0, Message: "OK"}

func TestConfigPlugin(t *testing.T) {
	var called bool
	plugin := NewPlugin("mock", func(context.Context) (map[string]string, error) {
		called = true
		return map[string]string{
			"conf1": "foobar",
		}, nil
	})

	// Basic methods
	assert.Equal(t, "config", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping(context.Background()))
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Call with good action
	resp, err := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "genConfig"})
	assert.True(t, called)
	assert.NoError(t, err)
	assert.Equal(t, osquery.ExtensionPluginResponse{{"conf1": "foobar"}}, resp)
}

func TestConfigPluginErrors(t *testing.T) {
	var called bool
	plugin := NewPlugin("mock", func(context.Context) (map[string]string, error) {
		called = true
		return nil, errors.New("foobar")
	})

	// Call with bad actions
	_, err := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{})
	assert.Error(t, err)
	assert.False(t, called)
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"})
	assert.Error(t, err)
	assert.False(t, called)

	// Call with good action but generate fails
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "genConfig"})
	assert.True(t, called)
	assert.Error(t, err)
	assert.Equal(t, "error getting config: foobar", err.Error())
}
