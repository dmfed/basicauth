package basicauth

import (
	"errors"
	"fmt"
	"log"
	"time"
)

var (
	// ErrInvalidPassword is returned when provided password does not check our with stored hash
	ErrInvalidPassword = errors.New("auth error: password does not check out with stored value")
	// ErrMustChangePassword is returned when newly created user tries to login with default pass
	ErrMustChangePassword = errors.New("auth error: user is required to change password")
	// ErrSamePassword is returned when trying to replace user password with the same password
	ErrSamePassword = errors.New("auth error: old password and new password must not match")
	// ErrUserExists is returned when trying to add user with existing username
	ErrUserExists = errors.New("auth error: user already exists")
)

// ExposedInterface is an interface intended to be exposed to outside world / client application
// It requires current user password for any interaction.
// It can only add/change/delete userinfo. For keepeing login sessions see
// LoginManager interface
type AppInterface interface {
	CheckUserPassword(username string, password string) error
	AddUser(username string, password string) error
	ChangeUserPassword(username string, oldpassword string, newpassword string) error
	DelUser(username string, password string) error
	GetUserInfo(username, password string) (UserInfo, error)
	UpdateUserInfo(username, password string, newinfo UserInfo) error
}

// Exposed holds ExposedInterface
type appinterface struct {
	UserAccountStorage
	PasswordHasher
}

// NewExposedInterface creates instnce of Exposed
func NewAppInterface(st UserAccountStorage) (AppInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &appinterface{st, globalHasher}, nil
}

// CheckUserPassword fetches UserInfo from underlying UserInfoStorage and uses
// package default hasher to compare provided password with stored hash.
// Returns nil is password checks out else error.
// If fetch from starage fails returns underlying error.
func (app *appinterface) CheckUserPassword(username string, password string) error {
	account, err := app.Get(username)
	if err != nil {
		return err
	}
	if account.MustChangePassword {
		return ErrMustChangePassword
	}
	err = app.CompareUserPasswordWithHash(account.PasswordHash, password)
	if err != nil {
		account.FailedLoginAttempts++
		err = ErrInvalidPassword
	} else {
		account.Lastlogin = time.Now()
	}
	if e := app.Upd(account); e != nil {
		log.Printf("error putting userinfo: %v", e)
	}
	return err
}

// AddUser adds new UserInfo to underlying IserInfoStorage.
func (app *appinterface) AddUser(username string, password string) error {
	_, err := app.Get(username)
	if err == nil {
		return ErrUserExists
	}
	hash, err := app.HashPassword(password)
	if err != nil {
		return err
	}
	t := time.Now()
	var account Account
	account.UserName = username
	account.PasswordHash = hash
	account.DateCreated = t
	account.DateChanged = t
	account.FailedLoginAttempts = 0
	return app.Put(account)
}

// DelUser deletes UserInfo with UserName == username from underlying
// UserInfoStorage.
func (app *appinterface) DelUser(username string, password string) error {
	account, err := app.Get(username)
	if err != nil {
		return err
	}
	if err := app.CompareUserPasswordWithHash(account.PasswordHash, password); err != nil {
		return err
	}
	return app.Del(username)
}

// ChangeUserPassword fetches UserInfo for username from storage, verifies user current password,
// hashes new password and updates UserInfo in underlying storage.
func (app *appinterface) ChangeUserPassword(username string, oldpassword string, newpassword string) error {
	if oldpassword == newpassword {
		return ErrSamePassword
	}
	account, err := app.Get(username)
	if err != nil {
		return err
	}
	if !account.MustChangePassword {
		err := app.CompareUserPasswordWithHash(account.PasswordHash, oldpassword)
		if err != nil {
			return err
		}
	}
	hash, err := app.HashPassword(newpassword)
	if err != nil {
		return err
	}
	account.PasswordHash = hash
	account.DateChanged = time.Now()
	return app.Upd(account)
}

func (app *appinterface) GetUserInfo(username, password string) (UserInfo, error) {
	account, err := app.Get(username)
	if err != nil {
		return UserInfo{}, err
	}
	if err := app.CompareUserPasswordWithHash(account.PasswordHash, password); err != nil {
		return UserInfo{}, ErrInvalidPassword
	}
	return account.User, nil
}

func (app *appinterface) UpdateUserInfo(username, password string, newinfo UserInfo) error {
	account, err := app.Get(username)
	if err != nil {
		return err
	}
	if err := app.CompareUserPasswordWithHash(account.PasswordHash, password); err != nil {
		return ErrInvalidPassword
	}
	account.User = newinfo
	account.DateChanged = time.Now()
	return app.Put(account)
}
