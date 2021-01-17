package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/config"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()

	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(config.NewPlugin("example_config", GenerateConfigs))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func GenerateConfigs(ctx context.Context) (map[string]config.Config, error) {
	return map[string]config.Config{
		"config1": {
			Options: map[string]interface{}{
				"host_identifier":        "hostname",
				"schedule_splay_percent": 10,
			},
			Schedule: map[string]config.Query{
				"macos_kextstat": {
					Query:    "SELECT * from kernel_extensions;",
					Interval: 10,
				},
				"foobar": {
					Query:    "SELECT foo, bar, pid FROM foobar_table;",
					Interval: 600,
				},
			},
		},
	}, nil
}
