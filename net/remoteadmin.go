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

type AuthAdmin struct {
	ipAddr     string
	adminToken string
	secure     bool
}

// NewAdminClient returns basicauth.AdminInterface with two methods added
// It implements AdminAddAppToken(token string) and AdminReplaceAdminToken(token string)
// These methods are used to remotely change valid tokens for connecting apps.
func NewAdminClient(ip, port, admintoken string, secure bool) (*AuthAdmin, error) {
	var aa AuthAdmin
	aa.ipAddr = "http://" + ip + ":" + port
	aa.adminToken = admintoken
	aa.secure = secure
	return &aa, nil
}

func (aa *AuthAdmin) AdminGetUserInfo(username string) (basicauth.UserInfo, error) {
	m := aa.messageTemplate()
	m.Request.Action = "admingetuserinfo"
	m.Request.UserName = username
	m, err := aa.post(m)
	if err != nil {
		return m.Response.UserInfo, err
	}
	if !m.Response.OK {
		return m.Response.UserInfo, fmt.Errorf("could not get user info for user %v: %v", username, m.Response.Error)
	}
	return m.Response.UserInfo, nil
}

func (aa *AuthAdmin) AdminUpdUserInfo(userinfo basicauth.UserInfo) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminupdateuserinfo"
	m.Request.UserInfo = userinfo
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not update user info for user %v: %v", userinfo.UserName, m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminResetUserPassword(username string) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminresetuserinfo"
	m.Request.UserName = username
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not reset password for user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminAddUser(username string) (err error) {
	m := aa.messageTemplate()
	m.Request.Action = "adminadduser"
	m.Request.UserName = username
	m, err = aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not add user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminDelUser(username string) error {
	m := aa.messageTemplate()
	m.Request.Action = "admindeluser"
	m.Request.UserName = username
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not delete user %v: %v", username, m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminAddAppToken(token string) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminaddapptoken"
	m.Request.Token = token
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could add token: %v", m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminDelAppToken(token string) error {
	m := aa.messageTemplate()
	m.Request.Action = "admindelapptoken"
	m.Request.Token = token
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could delete token: %v", m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminToggleAppToken(token string) error {
	m := aa.messageTemplate()
	m.Request.Action = "admintoggleapptoken"
	m.Request.Token = token
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could toggle token: %v", m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminReplaceAdminToken(token string) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminreplaceadmintoken"
	m.Request.Token = token
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could add token: %v", m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) post(inpmessage Message) (m Message, err error) {
	resp, err := http.Post(aa.ipAddr, "application/json", bytes.NewReader(inpmessage.ToBytes()))
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

func (aa *AuthAdmin) messageTemplate() Message {
	var m Message
	m.AppToken = aa.adminToken
	// TODO Handle ids in some way
	// m.Request.ID = "0000"
	return m
}
