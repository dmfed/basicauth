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
	CheckUserPassword(username, password string) error
	AddUser(username, password string) error
	DelUser(username, password string) error
	ChangeUserPassword(username, oldpassword, newpassword string) error
	GetUserInfo(username, password string) (UserInfo, error)
	UpdateUserInfo(username, password string, newinfo UserInfo) error
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
	tk, _ := NewMemTokenKeeper(time.Hour * 24)
	return &loginmanager{exposed, tk}, nil
}

func (lm *loginmanager) Login(username, password string) (token string, err error) {
	if err = lm.ex.CheckUserPassword(username, password); err != nil {
		return
	}
	if _, err := lm.tk.GetUserToken(username); err == nil {
		if err := lm.tk.DelUserToken(username); err != nil {
			return "", err
		}
	}
	return lm.tk.NewUserToken(username)
}

func (lm *loginmanager) Logout(username string) error {
	return lm.tk.DelUserToken(username)
}

func (lm *loginmanager) CheckUserLoggedIn(username, token string) error {
	validtoken, err := lm.tk.GetUserToken(username)
	if err != nil {
		return err
	}
	if token != validtoken {
		return ErrInvalidToken
	}
	return nil
}

func (lm *loginmanager) CheckUserPassword(username, password string) error {
	return lm.ex.CheckUserPassword(username, password)
}

func (lm *loginmanager) AddUser(username, password string) error {
	return lm.ex.AddUser(username, password)
}

func (lm *loginmanager) DelUser(username, password string) error {
	lm.tk.DelUserToken(username)
	if err := lm.ex.DelUser(username, password); err != nil {
		return err
	}
	return nil
}

func (lm *loginmanager) ChangeUserPassword(username, oldpassword, newpassword string) (err error) {
	if err = lm.ex.ChangeUserPassword(username, oldpassword, newpassword); err != nil {
		lm.tk.DelUserToken(username)
		return
	}
	lm.tk.DelUserToken(username)
	return
}

func (lm *loginmanager) GetUserInfo(username, password string) (UserInfo, error) {
	return lm.ex.GetUserInfo(username, password)
}

func (lm *loginmanager) UpdateUserInfo(username, password string, newinfo UserInfo) error {
	return lm.ex.UpdateUserInfo(username, password, newinfo)
}
