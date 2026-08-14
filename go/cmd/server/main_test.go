package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeWaitsForInflightRequestDuringShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		response.WriteHeader(http.StatusNoContent)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- serve(ctx, server, listener, time.Second, logger)
	}()

	requestResult := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			response.Body.Close()
		}
		requestResult <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-serveResult:
		t.Fatalf("serve returned before request drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-requestResult; err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}
