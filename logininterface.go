package basicauth

import (
	"fmt"
	"time"
)

// LoginManager implements similar functionality to
// ExposedInterface but keeps track of session tokens.
type LoginInterface interface {
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

type logininterface struct {
	AppInterface
	TokenKeeper
}

// NewLoginManager return instance of LoginManager interface
func NewLoginManager(st UserAccountStorage) (LoginInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("failed to instantiate LoginManager: ex is nil")
	}
	app, _ := NewAppInterface(st)
	tk, _ := NewMemTokenKeeper(time.Hour * 24)
	return &logininterface{app, tk}, nil
}

func (lm *logininterface) Login(username, password string) (token string, err error) {
	if err = lm.CheckUserPassword(username, password); err != nil {
		return
	}
	if _, err := lm.GetUserToken(username); err == nil {
		if err := lm.DelUserToken(username); err != nil {
			return "", err
		}
	}
	return lm.NewUserToken(username)
}

func (lm *logininterface) Logout(username string) error {
	return lm.DelUserToken(username)
}

func (lm *logininterface) CheckUserLoggedIn(username, token string) error {
	validtoken, err := lm.GetUserToken(username)
	if err != nil {
		return err
	}
	if token != validtoken {
		return ErrInvalidToken
	}
	return nil
}
