package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"runic/internal/agent"
)

func main() {
	controlPlaneURL := flag.String("url", "", "Control plane URL (or RUNIC_CONTROL_PLANE_URL env)")
	configPath := flag.String("config", "/etc/runic-agent/config.json", "Config file path")
	flag.Parse()

	if *controlPlaneURL == "" {
		*controlPlaneURL = os.Getenv("RUNIC_CONTROL_PLANE_URL")
	}

	a := agent.New(*configPath, *controlPlaneURL)

	// Context that cancels on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Received shutdown signal — stopping agent...")
		cancel()
	}()

	if err := a.Run(ctx); err != nil {
		log.Fatalf("agent error: %v", err)
	}
}
