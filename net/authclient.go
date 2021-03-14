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

type authAdmin struct {
	ipAddr     string
	adminToken string
	secure     bool
}

func NewAdminClient(ip, port, admintoken string, secure bool) (basicauth.AdminInterface, error) {
	var ac authAdmin
	ac.ipAddr = "http://" + ip + ":" + port
	ac.adminToken = admintoken
	ac.secure = secure
	return &ac, nil
}

func (ac *authAdmin) AdminGetUserInfo(username string) (basicauth.UserInfo, error) {
	m := ac.messageTemplate()
	m.Request.Action = "admingetuserinfo"
	m.Request.UserName = username
	m, err := ac.post(m)
	if err != nil {
		return m.Response.UserInfo, err
	}
	if !m.Response.OK {
		return m.Response.UserInfo, fmt.Errorf("could not get user info for user %v: %v", username, m.Response.Error)
	}
	return m.Response.UserInfo, nil
}

func (ac *authAdmin) AdminUpdateUserInfo(userinfo basicauth.UserInfo) error {
	m := ac.messageTemplate()
	m.Request.Action = "adminupdateuserinfo"
	m.Request.UserInfo = userinfo
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not update user info for user %v: %v", userinfo.UserName, m.Response.Error)
	}
	return nil
}

func (ac *authAdmin) AdminResetUserPassword(username string) error {
	m := ac.messageTemplate()
	m.Request.Action = "adminresetuserinfo"
	m.Request.UserName = username
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not reset password for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authAdmin) AdminAddUser(username string) (err error) {
	m := ac.messageTemplate()
	m.Request.Action = "adminadduser"
	m.Request.UserName = username
	m, err = ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not add user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authAdmin) AdminDelUser(username string) error {
	m := ac.messageTemplate()
	m.Request.Action = "admindeluser"
	m.Request.UserName = username
	m, err := ac.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not delete user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (ac *authAdmin) post(inpmessage Message) (m Message, err error) {
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

func (ac *authAdmin) messageTemplate() Message {
	var m Message
	m.AppToken = ac.adminToken
	m.Request.ID = "0000"
	return m
}
