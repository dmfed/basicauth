package net

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dmfed/basicauth"
)

var (
	ErrConnectionFailed = errors.New("error: connection to server failed")
)

type authClient struct {
	ipAddr   string
	appToken string
	secure   bool
}

func NewClient(ip, port, apptoken string, secure bool) (basicauth.LoginManager, error) {
	var ac authClient
	ac.ipAddr = "http://" + ip + ":" + port
	ac.appToken = apptoken
	ac.secure = secure
	return &ac, nil
}

func (ac *authClient) Login(username, password string) (token string, err error) {
	m := ac.messageTemplate()
	m.Request.Action = "login"
	m.Request.UserName = username
	m.Request.Password = password
	m, err = ac.post(m)
	if err != nil {
		return "", err
	}
	if !m.Response.OK {
		return "", fmt.Errorf("could not login user %v: %v", username, m.Response.Error)
	}
	return m.Response.Token, nil
}

func (ac *authClient) Logout(username string) error {
	m := ac.messageTemplate()
	m.Request.Action = "logout"
	m.Request.UserName = username
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not logout user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) CheckUserLoggedIn(username, token string) error {
	m := ac.messageTemplate()
	m.Request.Action = "checkuserloggedin"
	m.Request.UserName = username
	m.Request.Token = token
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("error checking session for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) AddUser(username, password string) (token string, err error) {
	m := ac.messageTemplate()
	m.Request.Action = "adduser"
	m.Request.UserName = username
	m.Request.Password = password
	m, err = ac.post(m)
	if err != nil {
		return "", err
	}
	if !m.Response.OK {
		return "", fmt.Errorf("could not add user %v: %v", username, m.Response.Error)
	}
	return m.Response.Token, nil
}

func (ac *authClient) DelUser(username, password string) error {
	m := ac.messageTemplate()
	m.Request.Action = "deluser"
	m.Request.UserName = username
	m.Request.Password = password
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not delete user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) ChangeUserPassword(username, password, newpassword string) (token string, err error) {
	m := ac.messageTemplate()
	m.Request.Action = "changeuserpassword"
	m.Request.UserName = username
	m.Request.Password = password
	m.Request.NewPassword = newpassword
	m, err = ac.post(m)
	if err != nil {
		return "", err
	}
	if !m.Response.OK {
		return "", fmt.Errorf("could not change user password for %v: %v", username, m.Response.Error)
	}
	return m.Response.Token, nil
}

func (ac *authClient) post(inpmessage Message) (m Message, err error) {
	resp, err := http.Post(ac.ipAddr, "application/json", bytes.NewReader(inpmessage.ToBytes()))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if err = m.FromBytes(data); err != nil {
		return
	}
	return
}

func (ac *authClient) messageTemplate() Message {
	var m Message
	m.AppToken = ac.appToken
	m.Request.ID = "0000"
	return m
}
