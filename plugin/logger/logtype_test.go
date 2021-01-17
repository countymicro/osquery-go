package logger

import "testing"

func TestDifferentialResult(t *testing.T) {
	l := RequestToLog(map[string]string{
		"category": "event",
		"string":   `{"name":"pack/tls@eventing-pack/socket_events","hostIdentifier":"564D1C61-8978-9934-D47A-7011D6B23BEA","calendarTime":"Sun Jan 17 14:43:22 2021 UTC","unixTime":1610894602,"epoch":0,"counter":0,"numerics":false,"decorations":{"host_uuid":"564D1C61-8978-9934-D47A-7011D6B23BEA","hostname":"local","serial":"serialNumber","username":"user"},"columns":{"action":"connect","auid":"501","family":"2","fd":"1f","local_address":"0","local_port":"0","path":"/usr/local/bin/osqueryd","pid":"26075","remote_address":"54.194.163.85","remote_port":"443","success":"0","time":"1610821751","uptime":"103726"},"action":"added"}`,
	})

	diff, ok := l.(*DifferentialResult)
	if !ok {
		t.Fatalf("DifferentialResult not parsed as such, got %T", l)
	}

	if diff.Name != "pack/tls@eventing-pack/socket_events" {
		t.Fatal("Name not parsed correctly")
	}
	if len(diff.Columns) == 0 {
		t.Fatal("Columns not parsed", diff.Columns)
	}
}
