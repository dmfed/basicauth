package basicauth

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidPassword is returned when provided password does not check our with stored hash
	ErrInvalidPassword = errors.New("auth error: password does not check out with stored value")
	// ErrSamePassword is returned when trying to replace user password with the same password
	ErrSamePassword = errors.New("auth error: old password and new password must not match")
)

// ExposedInterface is an interface intended to be exposed to outside world
// It requires current user password for any interaction.
type ExposedInterface interface {
	CheckUserPassword(username string, password string) error
	AddUser(username string, password string) error
	ChangeUserPassword(username string, oldpassword string, newpassword string) error
	DelUser(username string, password string) error
}

// Exposed holds ExposedInterface
type exposed struct {
	UserInfoStorage
}

// NewExposed creates instnce of Exposed
func NewExposed(st UserInfoStorage) (ExposedInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &exposed{st}, nil
}

// CheckUserPassword fetches UserInfo from underlying UserInfoStorage and uses
// package default hasher to compare provided password with stored hash.
// Returns nil is password checks out else error.
// If fetch from starage fails returns underlying error.
func (ex *exposed) CheckUserPassword(username string, password string) error {
	userinfo, err := ex.Get(username)
	if err != nil {
		return err
	}
	if err := ex.checkUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	return nil
}

// AddUser adds new UserInfo to underlying IserInfoStorage.
func (ex *exposed) AddUser(username string, password string) error {
	_, err := ex.Get(username)
	if err == nil {
		return ErrUserExists
	}
	hash, err := globalHasher.HashPassword(password)
	if err != nil {
		return err
	}
	t := time.Now()
	var userinfo UserInfo
	userinfo.UserName = username
	userinfo.PasswordHash = hash
	userinfo.DateCreated = t
	userinfo.DateChanged = t
	userinfo.FailedLoginAttempts = 0
	return ex.Put(userinfo)
}

// DelUser deletes UserInfo with UserName == username from underlying
// UserInfoStorage.
func (ex *exposed) DelUser(username string, password string) error {
	userinfo, err := ex.Get(username)
	if err != nil {
		return err
	}
	if err := ex.checkUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	return ex.Del(username)
}

// ChangeUserPassword fetches UserInfo for username from storage, verifies user current password,
// hashes new password and updates UserInfo in underlying storage.
func (ex *exposed) ChangeUserPassword(username string, oldpassword string, newpassword string) error {
	if oldpassword == newpassword {
		return ErrSamePassword
	}
	userinfo, err := ex.Get(username)
	if err != nil {
		return err
	}
	if err := ex.checkUserPassword(userinfo.PasswordHash, oldpassword); err != nil {
		return err
	}
	hash, err := globalHasher.HashPassword(newpassword)
	if err != nil {
		return err
	}
	userinfo.PasswordHash = hash
	userinfo.DateChanged = time.Now()
	return ex.Update(userinfo)
}

func (ex *exposed) checkUserPassword(hash string, password string) error {
	if err := globalHasher.CheckUserPassword(hash, password); err != nil {
		return ErrInvalidPassword
	}
	return nil
}
