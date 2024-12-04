package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v9"

	"github.com/mariomac/rdns/pkg/config"
	"github.com/mariomac/rdns/pkg/rdns"
)

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	cfg := config.DefaultConfig
	if err := env.Parse(&cfg); err != nil {
		slog.Error("reading env vars", "error", err)
		os.Exit(-1)
	}
	if err := lvl.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	if err := rdns.Run(ctx, &cfg); err != nil {
		slog.Error("running RDNS pipeline", "error", err)
		os.Exit(-1)
	}
}
