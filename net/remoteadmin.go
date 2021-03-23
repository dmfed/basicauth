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
func NewRemoteAdminInterface(ip, port, admintoken string, secure bool) (basicauth.AdminInterface, error) {
	var aa AuthAdmin
	aa.ipAddr = "http://" + ip + ":" + port
	aa.adminToken = admintoken
	aa.secure = secure
	return &aa, nil
}

func (aa *AuthAdmin) AdminGetAccount(username string) (basicauth.Account, error) {
	m := aa.messageTemplate()
	m.Request.Action = "admingetaccount"
	m.Request.UserName = username
	m, err := aa.post(m)
	if err != nil {
		return m.Response.Account, err
	}
	if !m.Response.OK {
		return m.Response.Account, fmt.Errorf("could not get user info for user %v: %v", username, m.Response.Error)
	}
	return m.Response.Account, nil
}

func (aa *AuthAdmin) AdminUpdAccount(account basicauth.Account) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminupdateaccount"
	m.Request.Account = account
	m, err := aa.post(m)
	if err != nil {
		return err
	}
	if !m.Response.OK {
		return fmt.Errorf("could not update user info for user %v: %v", account.UserName, m.Response.Error)
	}
	return nil
}

func (aa *AuthAdmin) AdminResetUserPassword(username string) error {
	m := aa.messageTemplate()
	m.Request.Action = "adminresetuserpassword"
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

func (aa *AuthAdmin) AdminAddAccount(username string) (err error) {
	m := aa.messageTemplate()
	m.Request.Action = "adminaddaccount"
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

func (aa *AuthAdmin) AdminDelAccount(username string) error {
	m := aa.messageTemplate()
	m.Request.Action = "admindelaccount"
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

func (aa *AuthAdmin) post(inpmessage Message) (Message, error) {
	var m Message
	resp, err := http.Post(aa.ipAddr, "application/json", bytes.NewReader(inpmessage.ToBytes()))
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}
	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("server returned: %v", string(data))
	}
	if err = m.FromBytes(data); err != nil {
		return m, err
	}
	return m, nil
}

func (aa *AuthAdmin) messageTemplate() Message {
	var m Message
	m.AppToken = aa.adminToken
	// TODO Handle ids in some way
	// m.Request.ID = "0000"
	return m
}
