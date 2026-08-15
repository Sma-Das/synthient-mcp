package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sma-Das/synthient-mcp/go/internal/buildinfo"
	"github.com/Sma-Das/synthient-mcp/go/internal/config"
	"github.com/Sma-Das/synthient-mcp/go/internal/httpserver"
	"github.com/Sma-Das/synthient-mcp/go/internal/mcpserver"
	"github.com/Sma-Das/synthient-mcp/go/internal/synthient"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "version":
			fmt.Printf("synthient-mcp %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
			return
		case "healthcheck":
			if err := healthcheck(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "stdio":
			if err := runStdioCommand(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func runStdioCommand() error {
	apiKey := strings.TrimSpace(os.Getenv("SYNTHIENT_API_KEY"))
	if apiKey == "" || len(apiKey) > 1024 {
		return fmt.Errorf("stdio: SYNTHIENT_API_KEY must contain a bounded Synthient API key")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("stdio: invalid configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runStdio(ctx, cfg, apiKey)
}

func runStdio(ctx context.Context, cfg config.Config, apiKey string) error {
	httpClient := &http.Client{Timeout: cfg.RequestTimeout}
	client := synthient.NewClient(cfg.SynthientBaseURL, apiKey, "", httpClient).WithGRPCEndpoint(cfg.SynthientGRPCEndpoint)
	server := mcpserver.New(client, mcp.NewSchemaCache(), mcpserver.Options{
		LegacyToolNames: cfg.LegacyToolNames,
		SampleTimeout:   cfg.StreamTimeout,
	})
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("stdio MCP server: %w", err)
	}
	return nil
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	listener, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Address(), err)
	}
	defer listener.Close()
	server := newHTTPServer(cfg, httpserver.NewHandlerWithLogger(cfg, logger))
	logger.Info("Synthient MCP server listening",
		"url", httpserver.ListenAddress(cfg),
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"max_concurrent_requests", cfg.MaxConcurrentRequests,
	)
	return serve(ctx, server, listener, cfg.ShutdownTimeout, logger)
}

func newHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 20 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 20 * time.Second
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	maxHeaderBytes := cfg.MaxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 32768
	}
	return &http.Server{
		Addr:              cfg.Address(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

func serve(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration, logger *slog.Logger) error {
	if shutdownTimeout <= 0 {
		shutdownTimeout = 10 * time.Second
	}
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownErr := server.Shutdown(shutdownContext)
	serveErr := <-serveErrors
	if shutdownErr != nil {
		_ = server.Close()
		return fmt.Errorf("graceful shutdown: %w", shutdownErr)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

func newLogger(cfg config.Config) *slog.Logger {
	options := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogJSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, options))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, options))
}

func healthcheck() error {
	port := 3000
	if value := os.Getenv("PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			return fmt.Errorf("healthcheck: invalid PORT")
		}
		port = parsed
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz")
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: HTTP %d", response.StatusCode)
	}
	return nil
}
