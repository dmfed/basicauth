package net

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dmfed/basicauth"
)

var (
	ErrLoginManagerIsNil = errors.New("error creating server: LoginManager is nil")
)

// NewLoginServer creates instance of http/https server which accepts incoming connections on specified
// ip and port. The server can be lauched with ListenAndServe() or ListenAndServeTLS() methods
// It is callers responsibility to gracefully shutdown server with Shutdown() not Close()
// in order to disconnect from password keeper gracefully
func NewLoginServer(ip, port, apptoken string, lm basicauth.LoginManager) (*http.Server, error) {
	if lm == nil {
		return nil, ErrLoginManagerIsNil
	}

	var loginhandler HTTPLoginHandler
	loginhandler.apptoken = apptoken
	loginhandler.lm = lm
	http.Handle("/login", &loginhandler)

	var adminhandler HTTPAdminHandler
	http.Handle("/admin", &adminhandler)

	server := &http.Server{Addr: ip + ":" + port} // no Handler provided, will use default mux
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

type HTTPLoginHandler struct {
	lm       basicauth.LoginManager
	apptoken string
}

func (h *HTTPLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bodydata, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, "could not read request body", http.StatusNoContent)
		return
	}
	var msg Message
	if err := msg.FromBytes(bodydata); err != nil {
		log.Printf("error unmarshalling message: %v", err)
		http.Error(w, "could not parse request body", http.StatusNoContent)
		return
	}
	if msg.AppToken != h.apptoken {
		log.Printf("error: got invalid app token %v", msg.AppToken)
		http.Error(w, "error: not authorised", 403)
		return
	}
	msg.Response = Response{}
	switch msg.Request.Action {
	case "login":
		token, err := h.lm.Login(msg.Request.UserName, msg.Request.Password)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Token = token
		msg.Response.Error = err.Error()
	case "logout":
		err := h.lm.Logout(msg.Request.UserName)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Error = err.Error()
	case "checkuserloggedin":
		err := h.lm.CheckUserLoggedIn(msg.Request.UserName, msg.Request.Token)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Token = msg.Request.Token
		msg.Response.Error = err.Error()
	case "adduser":
		token, err := h.lm.AddUser(msg.Request.UserName, msg.Request.Password)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Token = token
		msg.Response.Error = err.Error()
	case "deluser":
		err := h.lm.DelUser(msg.Request.UserName, msg.Request.Password)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Error = err.Error()
	case "changeuserpassword":
		token, err := h.lm.ChangeUserPassword(msg.Request.UserName, msg.Request.Password, msg.Request.NewPassword)
		if err == nil {
			msg.Response.OK = true
		}
		msg.Response.Token = token
		msg.Response.Error = err.Error()
	default:
		msg.Response.OK = false
		msg.Response.Error = "could not process Message"
	}
	msg.Request = Request{}
	w.Header().Set("Content-Type", "application/json")
	if msg.Response.OK {
		w.WriteHeader(200)
	}
	w.Write(msg.ToBytes())
}

type HTTPAdminHandler struct {
	admin      basicauth.AdminInterface
	admintoken string
}

func (adm *HTTPAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("you've reached admin interface"))
}
