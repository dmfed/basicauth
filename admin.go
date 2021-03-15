package basicauth

import (
	"errors"
	"fmt"
	"time"
)

var defaultPassword = "none"

var (
	// ErrUserExists is returned when trying to add user with existing username
	ErrUserExists = errors.New("auth error: user already exists")
)

// AdminInterface defines methods to add, delete and update user info
// it does not require user password to perform where possible.
type AdminInterface interface {
	AdminAddUser(username string) error //Change to return random password
	AdminDelUser(username string) error
	AdminGetUserInfo(username string) (UserInfo, error)
	AdminUpdUserInfo(UserInfo) error
	AdminResetUserPassword(username string) error
}

// Admin is a struct to implement AdminInterface
type admin struct {
	UserInfoStorage
	PasswordHasher
}

// NewAdminInterface creates instance of AdminInterface
func NewAdminInterface(st UserInfoStorage) (AdminInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &admin{st, globalHasher}, nil
}

// AdminGetUserInfo returns stored UerInfo if available in the storage
func (ad *admin) AdminGetUserInfo(username string) (UserInfo, error) {
	return ad.Get(username)
}

// AdminAddUser add new user (if storage allows )
func (ad *admin) AdminAddUser(username string) error {
	if _, err := ad.Get(username); err == nil {
		return ErrUserExists
	}
	hash, err := ad.HashPassword(defaultPassword)
	if err != nil {
		return err
	}
	t := time.Now()
	return ad.Put(UserInfo{UserName: username, PasswordHash: hash, DateCreated: t, DateChanged: t, MustChangePassword: true}) // TODO
}

// AdminDelUser deletes user
func (ad *admin) AdminDelUser(username string) error {
	return ad.Del(username)
}

// AdminUpdateUserInfo updates userinfo in underlying USerInfoStorage
func (ad *admin) AdminUpdUserInfo(userinfo UserInfo) error {
	existing, err := ad.Get(userinfo.UserName)
	if err != nil {
		return err
	}
	userinfo.PasswordHash = existing.PasswordHash
	return ad.Upd(userinfo)
}

// AdminUpdateUserPassword updates user's password hash in underlying storage
func (ad *admin) AdminResetUserPassword(username string) error {
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
