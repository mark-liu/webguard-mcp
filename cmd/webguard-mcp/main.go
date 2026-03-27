package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mark-liu/webguard-mcp/internal/audit"
	"github.com/mark-liu/webguard-mcp/internal/config"
	"github.com/mark-liu/webguard-mcp/internal/server"
)

var version = "0.6.0"

func main() {
	configPath := flag.String("config", "", "path to config file (default: ~/.config/webguard-mcp/config.yaml)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("webguard-mcp %s\n", version)
		os.Exit(0)
	}

	// Load config
	cfgPath := *configPath
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Set up audit logger
	auditPath := cfg.Audit.Path
	if auditPath == "" {
		auditPath = audit.DefaultPath()
	}
	auditLogger, err := audit.New(auditPath, cfg.Audit.Enabled)
	if err != nil {
		log.Fatalf("failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	// Create server
	srv := server.New(cfg, auditLogger, version)

	// Set up SIGHUP for config reload
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			newCfg, err := config.Load(cfgPath)
			if err != nil {
				log.Printf("SIGHUP: failed to reload config: %v", err)
				continue
			}
			srv.ReloadConfig(newCfg)
			log.Printf("SIGHUP: config reloaded from %s", cfgPath)
		}
	}()

	// Run blocks until the transport closes or errors.
	if err := srv.Run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
