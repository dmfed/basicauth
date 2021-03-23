package net

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/dmfed/basicauth"
)

type authClient struct {
	schema   string
	ipAddr   string
	appToken string
	secure   bool
}

func NewRemoteAppInterface(ip, port, apptoken string, requireTLS bool) (basicauth.AppInterface, error) {
	return getAC(ip, port, apptoken, requireTLS), nil
}

func NewRemodeLoginInterface(ip, port, apptoken string, requireTLS bool) (basicauth.LoginInterface, error) {
	return getAC(ip, port, apptoken, requireTLS), nil
}

func getAC(ip, port, apptoken string, requireTLS bool) *authClient {
	var ac authClient
	switch requireTLS {
	case true:
		ac.schema = "https://"
	default:
		ac.schema = "http://"
	}
	ac.ipAddr = ip + ":" + port
	ac.appToken = apptoken
	ac.secure = requireTLS // TODO
	return &ac
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
		return fmt.Errorf("could not comnfirm user %v status: %v", username, m.Response.Error)
	}
	return nil
}
func (ac *authClient) CheckUserPassword(username, password string) error {
	m := ac.messageTemplate()
	m.Request.Action = "checkuserpassword"
	m.Request.UserName = username
	m.Request.Password = password
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("error checking password for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) AddUser(username, password string) (err error) {
	m := ac.messageTemplate()
	m.Request.Action = "adduser"
	m.Request.UserName = username
	m.Request.Password = password
	m, err = ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not add user %v: %v", username, m.Response.Error)
	}
	return nil
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

func (ac *authClient) ChangeUserPassword(username, oldpassword, newpassword string) error {
	m := ac.messageTemplate()
	m.Request.Action = "changeuserpassword"
	m.Request.UserName = username
	m.Request.Password = oldpassword
	m.Request.NewPassword = newpassword
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not reset password for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) GetUserInfo(username, password string) (basicauth.UserInfo, error) {
	m := ac.messageTemplate()
	m.Request.Action = "getuserinfo"
	m.Request.UserName = username
	m.Request.Password = password
	m, err := ac.post(m)
	if err != nil {
		return m.Response.UserInfo, err
	}
	if !m.Response.OK {
		return basicauth.UserInfo{}, fmt.Errorf("could not get user info for user %v: %v", username, m.Response.Error)
	}
	return m.Response.UserInfo, nil
}

func (ac *authClient) UpdateUserInfo(username, password string, newinfo basicauth.UserInfo) error {
	m := ac.messageTemplate()
	m.Request.Action = "updateuserinfo"
	m.Request.UserInfo = newinfo
	m.Request.Password = password
	m.Request.UserInfo = newinfo
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not update userinfo for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authClient) post(inpmessage Message) (m Message, err error) {
	resp, err := http.Post(ac.schema+ac.ipAddr, "application/json", bytes.NewReader(inpmessage.ToBytes()))
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
