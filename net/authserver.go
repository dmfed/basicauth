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
	ErrStorageIsNil = errors.New("NewLoginServer: error creating server: storage is nil")
)

// NewLoginServer creates instance of http/https server which accepts incoming connections on specified
// ip and port. The server can be lauched with ListenAndServe() or ListenAndServeTLS() methods
// It is callers responsibility to gracefully shutdown server with Shutdown() not Close()
// in order to disconnect from password keeper gracefully
func NewLoginServer(ip, port, apptoken string, admintoken string, st basicauth.UserInfoStorage) (*http.Server, error) {
	if st == nil {
		return nil, ErrStorageIsNil
	}
	logmgr, _ := basicauth.NewLoginManager(st)
	admin, _ := basicauth.NewAdmin(st)
	var loginhandler HTTPLoginHandler
	loginhandler.apptoken = apptoken
	loginhandler.admintoken = admintoken
	loginhandler.lm = logmgr
	loginhandler.admin = admin
	server := &http.Server{Addr: ip + ":" + port, Handler: &loginhandler}
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
	lm         basicauth.LoginManager
	admin      basicauth.AdminInterface
	apptoken   string
	admintoken string
}

func (h *HTTPLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bodydata, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading request body: %v", err)
		http.Error(w, "could not read request body", 400)
		return
	}
	var msg Message
	if err := msg.FromBytes(bodydata); err != nil {
		log.Printf("error unmarshalling message: %v", err)
		http.Error(w, "could not parse JSON from request body", 400)
		return
	}
	log.Printf("message AppToken: %v server token: %v \n", msg.AppToken, h.apptoken)
	if msg.AppToken == h.admintoken {
		msg = h.processAdminCommand(msg)
	} else if msg.AppToken == h.apptoken {
		msg = h.processCommonCommand(msg)
	} else {
		log.Printf("error: got invalid app token %v", msg.AppToken)
		http.Error(w, "error: no valid app token provided", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(msg.ToBytes())
}

func (h *HTTPLoginHandler) processCommonCommand(msg Message) Message {
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
		token, err := h.lm.AddUser(msg.Request.UserName, msg.Request.Password)
		log.Printf("Got token: %v, err: %v", token, err)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.Token = token

	case "deluser":
		err := h.lm.DelUser(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)
	case "changeuserpassword":
		token, err := h.lm.ChangeUserPassword(msg.Request.UserName, msg.Request.Password, msg.Request.NewPassword)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.Token = token
	default:
		msg.Response.OK = false
	}
	msg.Request = Request{}
	return msg
}

func (h *HTTPLoginHandler) processAdminCommand(msg Message) Message {
	msg.Response = Response{ID: msg.Request.ID}
	switch msg.Request.Action {
	// Applications should use these ones (LoginManager)
	case "admingetuserinfo":
		userinfo, err := h.admin.AdminGetUserInfo(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)
		msg.Response.UserInfo = userinfo

	case "adminupdateuserinfo":
		err := h.admin.AdminUpdateUserInfo(msg.Request.UserInfo)
		msg = appendErrorOKtoMessage(msg, err)

	case "adminadduser":
		err := h.admin.AdminAddUser(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "admindeluser":
		err := h.admin.AdminDelUser(msg.Request.UserName)
		msg = appendErrorOKtoMessage(msg, err)

	case "adminresetuserpassword":
		err := h.lm.CheckUserPassword(msg.Request.UserName, msg.Request.Password)
		msg = appendErrorOKtoMessage(msg, err)
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
