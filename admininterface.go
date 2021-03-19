package basicauth

import (
	"fmt"
	"time"
)

var defaultPassword = "none"

// AdminInterface defines methods to add, delete and update user info
// it does not require user password to perform where possible.
type AdminInterface interface {
	AdminAddAccount(username string) error //Change to return random password
	AdminDelAccount(username string) error
	AdminGetAccount(username string) (Account, error)
	AdminUpdAccount(Account) error
	AdminResetUserPassword(username string) error
}

// Admin is a struct to implement AdminInterface
type admininterface struct {
	UserAccountStorage
	PasswordHasher
}

// NewAdminInterface creates instance of AdminInterface
func NewAdminInterface(st UserAccountStorage) (AdminInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &admininterface{st, globalHasher}, nil
}

// AdminGetUserInfo returns stored UerInfo if available in the storage
func (ad *admininterface) AdminGetAccount(username string) (Account, error) {
	return ad.Get(username)
}

// AdminAddUser add new user (if storage allows )
func (ad *admininterface) AdminAddAccount(username string) error {
	if _, err := ad.Get(username); err == nil {
		return ErrUserExists
	}
	hash, err := ad.HashPassword(defaultPassword)
	if err != nil {
		return err
	}
	t := time.Now()
	return ad.Put(Account{UserName: username, PasswordHash: hash, DateCreated: t, DateChanged: t, MustChangePassword: true}) // TODO
}

// AdminDelUser deletes user
func (ad *admininterface) AdminDelAccount(username string) error {
	return ad.Del(username)
}

// AdminUpdateUserInfo updates userinfo in underlying USerInfoStorage
func (ad *admininterface) AdminUpdAccount(account Account) error {
	existing, err := ad.Get(account.UserName)
	if err != nil {
		return err
	}
	account.PasswordHash = existing.PasswordHash
	return ad.Upd(account)
}

// AdminUpdateUserPassword updates user's password hash in underlying storage
func (ad *admininterface) AdminResetUserPassword(username string) error {
	userinfo, err := ad.Get(username)
	if err != nil {
		return err
	}
	newhash, err := ad.HashPassword(defaultPassword)
	if err != nil {
		return err
	}
	userinfo.PasswordHash = newhash
	return ad.Upd(userinfo)
}
