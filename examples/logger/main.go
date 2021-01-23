package main

import (
	"context"
	"flag"
	"log"

	"github.com/bradleyjkemp/osquery-go"
	"github.com/bradleyjkemp/osquery-go/plugin/logger"
)

func main() {
	socketPath := flag.String("socket", "", "path to osqueryd extensions socket")
	flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Parse()

	server, err := osquery.NewExtensionManagerServer("example_logger", *socketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(logger.NewPlugin("example_logger", LogString))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func LogString(ctx context.Context, l logger.Log) error {
	log.Printf("%s: %s\n", l.Type(), l)
	return nil
}
