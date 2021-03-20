package net

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dmfed/basicauth"
)

var (
	// ErrStorageIsNil is returned when trying to pass nil value of UserInfoStorage to
	// NewLoginServer()
	ErrStorageIsNil = errors.New("NewLoginServer: error creating server: storage is nil")
)

// NewLoginServer creates instance of http/https server which accepts incoming connections on specified
// ip and port. The server can be lauched with ListenAndServe() or ListenAndServeTLS() methods
// It is callers responsibility to gracefully shutdown server with Shutdown() not Close()
// in order to disconnect from password keeper gracefully
func NewLoginServer(st basicauth.UserAccountStorage, ip, port, admintoken string, requireTLS bool, apptokens ...string) (*http.Server, error) {
	if st == nil {
		return nil, ErrStorageIsNil
	}
	logmgr, _ := basicauth.NewLoginManager(st, time.Hour*24)
	admin, _ := basicauth.NewAdminInterface(st)
	var lh apihandler
	lh.lm = logmgr
	lh.admin = admin
	lh.apptokens = make(map[string]bool)
	for _, tok := range apptokens {
		lh.apptokens[tok] = true
	}
	lh.admintoken = admintoken
	server := &http.Server{Addr: ip + ":" + port, Handler: &lh}
	// below lines are intended to handle case when there is
	// nobody to call call server.Shutdown() to exit gracefully
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-interrupts
		log.Printf("authserver exiting on signal: %v", sig)
		if err := st.Close(); err != nil {
			log.Printf("basicauth storage shutdown error: %v", err)
		}
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("basicauth authserver shutdown error: %v", err)
		}
	}()
	return server, nil
}

type apihandler struct {
	lm         basicauth.LoginInterface
	admin      basicauth.AdminInterface
	apptokens  map[string]bool
	admintoken string
}

func (h *apihandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
	}
	bodydata, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "400 could not read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	var msg Message
	if err := msg.FromBytes(bodydata); err != nil {
		http.Error(w, "400 could not parse JSON from request body", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(msg.Request.Action, "admin") && h.admintoken != "" && msg.AppToken == h.admintoken {
		msg = h.processAdminCommand(msg)
	} else if allowed, exists := h.apptokens[msg.AppToken]; allowed && exists {
		// && msg.AppToken != ""
		msg = h.processRegularCommand(msg)
	} else {
		log.Printf("error: got invalid app token %v from X-FWD: %v Addr: %v", msg.AppToken, r.Header.Get("X-FORWARDED-FOR"), r.RemoteAddr)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(msg.ToBytes())
}

func (h *apihandler) processRegularCommand(msg Message) Message {
	msg.Response = Response{ID: msg.Request.ID}
	switch msg.Request.Action {
	// Applications should use these ones (LoginManager)
	case "login":
		token, err := h.lm.Login(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.Token = token

	case "logout":
		err := h.lm.Logout(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "checkuserloggedin":
		err := h.lm.CheckUserLoggedIn(msg.Request.UserName, msg.Request.Token)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.Token = msg.Request.Token

	case "checkuserpassword":
		err := h.lm.CheckUserPassword(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)

	case "adduser":
		err := h.lm.AddUser(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)

	case "deluser":
		err := h.lm.DelUser(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)
	case "changeuserpassword":
		err := h.lm.ChangeUserPassword(msg.Request.UserName, msg.Request.Password, msg.Request.NewPassword)
		msg = appendErrorOKtoMessage(msg, err)
	default:
		msg.Response.OK = false
	}
	msg.Request = Request{}
	return msg
}

func (h *apihandler) processAdminCommand(msg Message) Message {
	msg.Response = Response{ID: msg.Request.ID}
	switch msg.Request.Action {
	case "admingetuseraccount":
		account, err := h.admin.AdminGetAccount(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.Account = account

	case "adminupdateaccount":
		err := h.admin.AdminUpdAccount(msg.Request.Account)
		msg = appendErrorOKtoMessage(msg, err)

	case "adminaddaccount":
		err := h.admin.AdminAddAccount(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "admindelaccount":
		err := h.admin.AdminDelAccount(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "adminresetuserpassword":
		err := h.admin.AdminResetUserPassword(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "adminaddapptoken":
		h.apptokens[msg.Request.Token] = true
		msg.Response.OK = true

	case "admindelapptoken":
		if _, ok := h.apptokens[msg.Request.Token]; ok {
			delete(h.apptokens, msg.Request.Token)
			msg.Response.OK = true
		} else {
			msg.Response.Error = "token not found"
			msg.Response.OK = false
		}

	case "admintoggleapptoken":
		if state, ok := h.apptokens[msg.Request.Token]; ok {
			h.apptokens[msg.Request.Token] = !state
			msg.Response.OK = true
		} else {
			msg.Response.Error = "token not found"
			msg.Response.OK = false
		}
	case "adminreplaceadmintoken":
		h.admintoken = msg.Request.Token
		msg.Response.OK = true
	default:
		msg.Response.OK = false
		msg.Response.Error = "unknown command supplied"
	}
	msg.Request = Request{}
	return msg
}

func appendErrorOKtoMessage(msg Message, err error) Message {
	if err != nil {
		msg.Response.Error = err.Error()
	} else {
		msg.Response.OK = true
	}
	return msg
}
