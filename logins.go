package basicauth

import (
	"fmt"
	"time"
)

// LoginManager implements similar functionality to
// ExposedInterface but keeps track of session tokens.
type LoginManager interface {
	Login(username, password string) (token string, err error)
	Logout(username string) error
	CheckUserLoggedIn(username, token string) error
	AddUser(username, password string) (token string, err error)
	DelUser(username, password string) error
	ChangeUserPassword(username, oldpassword, newpassword string) (token string, err error)
}

type loginmanager struct {
	ex ExposedInterface
	tk TokenKeeper
}

// NewLoginManager return instance of LoginManager interface
func NewLoginManager(st UserInfoStorage) (LoginManager, error) {
	if st == nil {
		return nil, fmt.Errorf("failed to instantiate LoginManager: ex is nil")
	}
	exposed, _ := NewExposedInterface(st)
	tk, _ := NewMemSessionTokenKeeper(time.Hour * 24)
	return &loginmanager{exposed, tk}, nil
}

func (lm *loginmanager) Login(username, password string) (token string, err error) {
	if err = lm.ex.CheckUserPassword(username, password); err != nil {
		return
	}
	return lm.tk.GenerateToken(username)
}

func (lm *loginmanager) Logout(username string) error {
	return lm.tk.DeleteUserToken(username)
}

func (lm *loginmanager) CheckUserLoggedIn(username, token string) error {
	return lm.tk.CheckToken(username, token)
}

func (lm *loginmanager) AddUser(username, password string) (token string, err error) {
	if err = lm.ex.AddUser(username, password); err != nil {
		return
	}
	return lm.tk.GenerateToken(username)
}

func (lm *loginmanager) DelUser(username, password string) error {
	lm.tk.DeleteUserToken(username)
	if err := lm.ex.DelUser(username, password); err != nil {
		return err
	}
	return nil
}

func (lm *loginmanager) ChangeUserPassword(username, oldpassword, newpassword string) (token string, err error) {
	if err = lm.ex.ChangeUserPassword(username, oldpassword, newpassword); err != nil {
		return
	}
	lm.tk.DeleteUserToken(username)
	return lm.tk.GenerateToken(username)
}
