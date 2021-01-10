package osquery

import (
	"context"
	"time"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/kolide/osquery-go/transport"
	"github.com/pkg/errors"

	"github.com/apache/thrift/lib/go/thrift"
)

// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
type ExtensionManagerClient struct {
	osquery.ExtensionManager
	transport thrift.TTransport
}

// NewClient creates a new client communicating to osquery over the socket at
// the provided path. If resolving the address or connecting to the socket
// fails, this function will error.
func NewClient(path string, timeout time.Duration) (*ExtensionManagerClient, error) {
	trans, err := transport.Open(path, timeout)
	if err != nil {
		return nil, err
	}

	client := osquery.NewExtensionManagerClientFactory(
		trans,
		thrift.NewTBinaryProtocolFactoryDefault(),
	)

	return &ExtensionManagerClient{client, trans}, nil
}

// Close should be called to close the transport when use of the client is
// completed.
func (c *ExtensionManagerClient) Close() {
	if c.transport != nil && c.transport.IsOpen() {
		c.transport.Close()
	}
}

// QueryRows is a helper that executes the requested query and returns the
// results. It handles checking both the transport level errors and the osquery
// internal errors by returning a normal Go error type.
func (c *ExtensionManagerClient) QueryRows(ctx context.Context, sql string) ([]map[string]string, error) {
	res, err := c.Query(ctx, sql)
	if err != nil {
		return nil, errors.Wrap(err, "transport error in query")
	}
	if res.Status == nil {
		return nil, errors.New("query returned nil status")
	}
	if res.Status.Code != 0 {
		return nil, errors.Errorf("query returned error: %s", res.Status.Message)
	}
	return res.Response, nil

}

// QueryRow behaves similarly to QueryRows, but it returns an error if the
// query does not return exactly one row.
func (c *ExtensionManagerClient) QueryRow(ctx context.Context, sql string) (map[string]string, error) {
	res, err := c.QueryRows(ctx, sql)
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, errors.Errorf("expected 1 row, got %d", len(res))
	}
	return res[0], nil
}
