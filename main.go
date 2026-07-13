package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mikhail-angelov/mproxy/proxy"
)

func main() {
	cfg, err := proxy.NewConfig()
	if err != nil {
		slog.Error("Cannot compose config", "error", err)
		os.Exit(1)
	}
	p := proxy.NewProxy(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := p.Run(ctx); err != nil {
		slog.Error("proxy stopped with error", "error", err)
		os.Exit(1)
	}
}
