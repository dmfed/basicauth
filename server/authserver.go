package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dmfed/basicauth"
)

// New creates instance of http/https server which accepts incoming connections on specified
// ip and port. The server can be lauched with ListenAndServe() or ListenAndServeTLS() methods
// It is callers responsibility to gracefully shutdown server with Shutdown() not Close()
// in order to disconnect from password keeper gracefully
func New(ip, port string, pk basicauth.PasswordKeeper, tk basicauth.TokenKeeper) (*http.Server, error) {
	var handler basicauth.HTTPHandler
	handler.PasswordKeeper = pk
	handler.TokenKeeper = tk
	server := &http.Server{Addr: ip + ":" + port,
		Handler: &handler}
	server.RegisterOnShutdown(handler.Close)
	// below lines are intended to handle case when there is
	// nobody to call call server.Shutdown() to exit gracefully
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)
	go func() {
		sig := <-interrupts
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		log.Printf("authserver exiting on signal: %v", sig)
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("authserver shutdown error: %v", err)
		} else {
			log.Println("authserver shut down gracefully")
		}
	}()
	return server, nil
}
