package basicauth

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidPassword = errors.New("auth error: password does not check out with stored value")
	ErrSamePassword    = errors.New("auth error: old password and new password must not match")
)

type ExposedInterface interface {
	CheckUserPassword(username string, password string) error
	AddUser(username string, password string) error
	ChangeUserPassword(username string, oldpassword string, newpassword string) error
	DelUser(username string, password string) error
}

type Exposed struct {
	Storage UserInfoStorage
}

func NewExposed(st UserInfoStorage) (ExposedInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &Exposed{st}, nil
}

func (ex *Exposed) CheckUserPassword(username string, password string) error {
	userinfo, err := ex.Storage.Get(username)
	if err != nil {
		return err
	}
	if err := ex.checkUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	return nil
}

func (ex *Exposed) AddUser(username string, password string) error {
	hash, err := globalHasher.HashPassword(password)
	if err != nil {
		return err
	}
	var userinfo UserInfo
	userinfo.UserName = username
	userinfo.PasswordHash = hash
	userinfo.DateRegistered = time.Now()
	userinfo.FailedLoginAttempts = 0
	return ex.Storage.Put(userinfo)
}

func (ex *Exposed) DelUser(username string, password string) error {
	userinfo, err := ex.Storage.Get(username)
	if err != nil {
		return err
	}
	if err := ex.checkUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	return ex.Storage.Del(username)
}

func (ex *Exposed) ChangeUserPassword(username string, oldpassword string, newpassword string) error {
	if oldpassword == newpassword {
		return ErrSamePassword
	}
	userinfo, err := ex.Storage.Get(username)
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
	return ex.Storage.Update(userinfo)
}

func (ex *Exposed) checkUserPassword(hash string, password string) error {
	if err := globalHasher.CheckUserPassword(hash, password); err != nil {
		return ErrInvalidPassword
	}
	return nil
}
