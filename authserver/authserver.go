package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	auth "github.com/dmfed/basicauth"
)

// Request is a representation of JSON request to the server.
// If sent with GET method will try to verify Username and Password.
// With PUT will add new user. With POST will try to update password.
// If sent with DEL will try to delete user.
type Request struct {
	Action      string            `json:"action"`
	Username    auth.UserName     `json:"username,omitempty"`
	Password    auth.Password     `json:"password,omitempty"`
	OldPassword auth.Password     `json:"oldpassword,omitempty"`
	Token       auth.SessionToken `json:"token,omitempty"`
}

// Response represents response from server
type Response struct {
	OK    bool              `json:"ok"`
	Token auth.SessionToken `json:"token,omitempty"`
	Error string            `json:"error"`
}

// MainHandler deals with all incoming requests
type mainHandler struct {
	PasswordKeeper     auth.PasswordKeeper
	SessionTokenKeeper auth.TokenKeeper
	// Implement stats
}

func newMainHandler(pwdfile string, tokenduration time.Duration) (*mainHandler, error) {
	handler := new(mainHandler)
	pk, err := auth.OpenJSONPasswordKeeper(pwdfile)
	if err != nil {
		log.Printf("error starting passwords keeper: %v", err)
		return handler, err
	}
	handler.PasswordKeeper = pk
	tk, err := auth.NewMemSessionTokenKeeper(tokenduration)
	if err != nil {
		log.Printf("error starting tokens keeper: %v", err)
		return handler, err
	}
	handler.SessionTokenKeeper = tk
	return handler, nil
}

func (h *mainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Server is running and accepting connections"))
}

// Close signals mainHandler to disconnect from password keeper and token keeper
// and Call their Close() method accordingly.
func (h *mainHandler) close() {
	if err := h.PasswordKeeper.Close(); err != nil {
		log.Printf("error closing passwords keeper: %v", err)
	}
	if err := h.SessionTokenKeeper.Close(); err != nil {
		log.Printf("error closing tokens keeper: %v", err)
	}
}

func main() {
	var (
		ipAddr        = flag.String("ip", "127.0.0.1", "ip address to listen on")
		port          = flag.String("port", "8081", "port to listen on")
		passwordsFile = flag.String("passwords", "", "password file to use")
		tokenDuration = flag.Duration("duration", time.Hour, "max duration while new token is valid")
		certFile      = flag.String("cert", "", "certificate file to use")
		keyFile       = flag.String("key", "", "key file to use")
	)
	flag.Parse()
	handler, err := newMainHandler(*passwordsFile, *tokenDuration)
	if err != nil {
		log.Printf("error starting auth server handler: %v", err)
		return
	}
	server := &http.Server{Addr: *ipAddr + ":" + *port,
		Handler: handler}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)
	go func() {
		sig := <-interrupts
		handler.close()
		log.Printf("exiting on signal: %v", sig)
		server.Close()
	}()
	if *certFile != "" && *keyFile != "" {
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
