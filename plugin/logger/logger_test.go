package logger

import (
	"context"
	"errors"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

type mockLoggerPlugin struct {
	NameFunc      func() string
	LogStringFunc func(context.Context, LogType, string) error
}

func (m *mockLoggerPlugin) Name() string {
	return m.NameFunc()
}

func (m *mockLoggerPlugin) LogString(ctx context.Context, typ LogType, log string) error {
	return m.LogStringFunc(ctx, typ, log)
}

func TestLoggerPlugin(t *testing.T) {
	var calledType LogType
	var calledLog string
	plugin := NewPlugin("mock", func(ctx context.Context, typ LogType, log string) error {
		calledType = typ
		calledLog = log
		return nil
	})

	StatusOK := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	// Basic methods
	assert.Equal(t, "logger", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping(context.Background()))
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Log string
	_, err := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"string": "logged string"})
	assert.NoError(t, err)
	assert.Equal(t, LogTypeString, calledType)
	assert.Equal(t, "logged string", calledLog)

	// Log snapshot
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"snapshot": "logged snapshot"})
	assert.NoError(t, err)
	assert.Equal(t, LogTypeSnapshot, calledType)
	assert.Equal(t, "logged snapshot", calledLog)

	// Log health
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"health": "logged health"})
	assert.NoError(t, err)
	assert.Equal(t, LogTypeHealth, calledType)
	assert.Equal(t, "logged health", calledLog)

	// Log init
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"init": "logged init"})
	assert.NoError(t, err)
	assert.Equal(t, LogTypeInit, calledType)
	assert.Equal(t, "logged init", calledLog)

	// Log status
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"status": "true", "log": `{"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: kernel: Cannot access \/dev\/osquery"},"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: scnetwork: Publisher not used"},"":{"s":"0","f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time"}}`})
	assert.NoError(t, err)
	assert.Equal(t, LogTypeStatus, calledType)
	assert.Equal(t, `{"s":"0","f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time"}`, calledLog)
}

func TestLogPluginErrors(t *testing.T) {
	var called bool
	plugin := NewPlugin("mock", func(ctx context.Context, typ LogType, log string) error {
		called = true
		return errors.New("foobar")
	})

	// Call with bad actions
	_, err := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{})
	assert.Error(t, err)
	assert.False(t, called)
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"})
	assert.Error(t, err)
	assert.False(t, called)

	// Call with empty status
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"status": "true", "log": ""})
	assert.Error(t, err)
	assert.False(t, called)

	// Call with good action but logging fails
	_, err = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"string": "logged string"})
	assert.True(t, called)
	assert.Error(t, err)
	assert.Equal(t, "error logging: foobar", err.Error())
}
