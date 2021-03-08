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

type AuthClient struct {
	ipAddr   string
	appToken string
	secure   bool
}

func NewClient(ip, port, apptoken string, secure bool) (basicauth.LoginManager, error) {
	var ac AuthClient
	ac.ipAddr = ip + ":" + port
	ac.appToken = apptoken
	ac.secure = secure
	return nil, nil
}

func (ac *AuthClient) Login(username, password string) (token string, err error) {
	m := ac.messageTemplate()
	m.Request.Action = "login"
	m.Request.UserName = username
	m.Request.Password = password
	resp, err := http.Post(ac.ipAddr, "application/json", bytes.NewReader(m.ToBytes()))
	if err != nil {
		return "", ErrConnectionFailed
	}
	defer resp.Body.Close()
	m = Message{}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := m.FromBytes(data); err != nil {
		return "", err
	}
	if !m.Response.OK {
		return "", fmt.Errorf("server returned error: %s", m.Response.Error)
	}
	return m.Response.Token, nil
}

func (ac *AuthClient) Logout(username string) error {
	m := ac.messageTemplate()
	m.Request.Action = "logout"
	m.Request.UserName = username
	return nil
}

func (ac *AuthClient) CheckUserLoggedIn(username, token string) error {
	m := ac.messageTemplate()
	m.Request.Action = "checkuserloggedin"
	m.Request.UserName = username
	return nil
}

func (ac *AuthClient) AddUser(username, password string) (token string, err error) {
	m := ac.messageTemplate()
	m.Request.Action = "adduser"
	m.Request.UserName = username
	m.Request.Password = password
	return "", nil
}

func (ac *AuthClient) DelUser(username, password string) error {
	m := ac.messageTemplate()
	m.Request.Action = "deluser"
	m.Request.UserName = username
	m.Request.Password = password
	return nil
}

func (ac *AuthClient) ChangeUserPassword(username, password, newpassword string) error {
	m := ac.messageTemplate()
	m.Request.Action = "changeuserpassword"
	m.Request.UserName = username
	m.Request.Password = password
	m.Request.NewPassword = newpassword
	return nil
}

func (ac *AuthClient) messageTemplate() Message {
	var m Message
	m.AppToken = ac.appToken
	m.Request.ID = "0000"
	return m
}
