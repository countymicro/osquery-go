package logger

import (
	"encoding/json"

	"github.com/bradleyjkemp/osquery-go/gen/osquery"
)

type LogType string

const (
	LogTypeStatus LogType = "status"
	LogTypeResult LogType = "result"
)

type Log interface {
	Type() LogType
	ToRequest() osquery.ExtensionPluginRequest
}

type Result interface {
	Log
	Metadata() *ResultMetadata
}

type ResultMetadata struct {
	Name           string `json:"name"`
	HostIdentifier string `json:"hostIdentifier"`
	// TODO: CalendarTime   time.Time         `json:"calendarTime"`
	UnixTime    int               `json:"unixTime"`
	Epoch       int               `json:"epoch"`
	Counter     int               `json:"counter"`
	Numerics    bool              `json:"numerics"`
	Decorations map[string]string `json:"decorations"`
	Action      string            `json:"action"`
}

func (r *ResultMetadata) Metadata() *ResultMetadata {
	return r
}

type DifferentialResult struct {
	Columns map[string]string `json:"columns"`
	*ResultMetadata
}

func (DifferentialResult) Type() LogType {
	return LogTypeResult
}

func (d DifferentialResult) ToRequest() osquery.ExtensionPluginRequest {
	payload, _ := json.Marshal(d)
	return map[string]string{
		"category": "event",
		"string":   string(payload),
	}
}

type SnapshotResult struct {
	*ResultMetadata
	Snapshot []map[string]string `json:"snapshot"`
}

func (SnapshotResult) Type() LogType {
	return LogTypeResult
}

func (s SnapshotResult) ToRequest() osquery.ExtensionPluginRequest {
	payload, _ := json.Marshal(s)
	return map[string]string{
		"snapshot": string(payload),
	}
}

type UnknownLog map[string]string

func (u UnknownLog) Type() LogType {
	return LogTypeStatus
}

func (u UnknownLog) ToRequest() osquery.ExtensionPluginRequest {
	return osquery.ExtensionPluginRequest(u)
}

func RequestToLog(req osquery.ExtensionPluginRequest) Log {
	switch {
	case req["category"] == "event":
		result := &DifferentialResult{}
		json.Unmarshal([]byte(req["string"]), result)
		return result

	case req["snapshot"] != "":
		result := &SnapshotResult{}
		json.Unmarshal([]byte(req["snapshot"]), result)
		return result

	default:
		return UnknownLog(req)
	}
}
