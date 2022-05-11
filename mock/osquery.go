// Automatically generated by mockimpl. DO NOT EDIT!

package mock

import (
	"context"

	"github.com/countymicro/osquery-go/gen/osquery"
)

var _ osquery.ExtensionManager = (*ExtensionManager)(nil)

type CloseFunc func()

type PingFunc func(ctx context.Context) (*osquery.ExtensionStatus, error)

type CallFunc func(ctx context.Context, registry string, item string, req osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error)

type ShutdownFunc func(ctx context.Context) error

type ExtensionsFunc func(ctx context.Context) (osquery.InternalExtensionList, error)

type RegisterExtensionFunc func(ctx context.Context, info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error)

type DeregisterExtensionFunc func(ctx context.Context, uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error)

type OptionsFunc func(ctx context.Context) (osquery.InternalOptionList, error)

type QueryFunc func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error)

type GetQueryColumnsFunc func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error)

type ExtensionManager struct {
	CloseFunc        CloseFunc
	CloseFuncInvoked bool

	PingFunc        PingFunc
	PingFuncInvoked bool

	CallFunc        CallFunc
	CallFuncInvoked bool

	ShutdownFunc        ShutdownFunc
	ShutdownFuncInvoked bool

	ExtensionsFunc        ExtensionsFunc
	ExtensionsFuncInvoked bool

	RegisterExtensionFunc        RegisterExtensionFunc
	RegisterExtensionFuncInvoked bool

	DeregisterExtensionFunc        DeregisterExtensionFunc
	DeregisterExtensionFuncInvoked bool

	OptionsFunc        OptionsFunc
	OptionsFuncInvoked bool

	QueryFunc        QueryFunc
	QueryFuncInvoked bool

	GetQueryColumnsFunc        GetQueryColumnsFunc
	GetQueryColumnsFuncInvoked bool
}

func (m *ExtensionManager) Close() {
	m.CloseFuncInvoked = true
	m.CloseFunc()
}

func (m *ExtensionManager) Ping(ctx context.Context) (*osquery.ExtensionStatus, error) {
	m.PingFuncInvoked = true
	return m.PingFunc(ctx)
}

func (m *ExtensionManager) Call(ctx context.Context, registry string, item string, req osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	m.CallFuncInvoked = true
	return m.CallFunc(ctx, registry, item, req)
}

func (m *ExtensionManager) Shutdown(ctx context.Context) error {
	m.ShutdownFuncInvoked = true
	return m.ShutdownFunc(ctx)
}

func (m *ExtensionManager) Extensions(ctx context.Context) (osquery.InternalExtensionList, error) {
	m.ExtensionsFuncInvoked = true
	return m.ExtensionsFunc(ctx)
}

func (m *ExtensionManager) RegisterExtension(ctx context.Context, info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	m.RegisterExtensionFuncInvoked = true
	return m.RegisterExtensionFunc(ctx, info, registry)
}

func (m *ExtensionManager) DeregisterExtension(ctx context.Context, uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
	m.DeregisterExtensionFuncInvoked = true
	return m.DeregisterExtensionFunc(ctx, uuid)
}

func (m *ExtensionManager) Options(ctx context.Context) (osquery.InternalOptionList, error) {
	m.OptionsFuncInvoked = true
	return m.OptionsFunc(ctx)
}

func (m *ExtensionManager) Query(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
	m.QueryFuncInvoked = true
	return m.QueryFunc(ctx, sql)
}

func (m *ExtensionManager) GetQueryColumns(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
	m.GetQueryColumnsFuncInvoked = true
	return m.GetQueryColumnsFunc(ctx, sql)
}
