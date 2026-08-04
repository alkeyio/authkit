package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/tniah/authkit/examples/config"
)

func main() {
	cfg := config.FromEnvVars(nil)
	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}))

	handler, err := SetupServer(cfg, lg)
	if err != nil {
		lg.Error("failed to set up server", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.Address, cfg.Port),
		Handler: handler,
	}

	lg.Info(fmt.Sprintf("server listening at http://%s:%s — press ctrl+c to stop", publicHost(cfg.Address), cfg.Port))
	if !errors.Is(srv.ListenAndServe(), http.ErrServerClosed) {
		lg.Error("server closed unexpectedly")
		os.Exit(1)
	}
}
