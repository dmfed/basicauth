package basicauth

import (
	"fmt"
	"time"
)

// AdminInterface defines methods to add, delete and update user info
// it does not require user password to perform where possible.
type AdminInterface interface {
	AdminAddUser(username string, password string) error //Change to return random password
	AdminDelUser(username string) error
	AdminGetUserInfo(username string) (UserInfo, error)
	AdminUpdateUserInfo(UserInfo) error
	AdminUpdateUserPassword(username, newpassword string) error
}

// Admin is a struct to implement AdminInterface
type admin struct {
	UserInfoStorage
	PasswordHasher
}

// NewAdmin creates instance of Admin and returns AdminInterface
func NewAdmin(st UserInfoStorage) (AdminInterface, error) {
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
func (ad *admin) AdminAddUser(username string, password string) error {
	if _, err := ad.Get(username); err == nil {
		return ErrUserExists
	}
	hash, err := ad.HashPassword(password)
	if err != nil {
		return err
	}
	t := time.Now()
	return ad.Put(UserInfo{UserName: username, PasswordHash: hash, DateCreated: t, DateChanged: t}) // TODO
}

// AdminDelUser deletes user
func (ad *admin) AdminDelUser(username string) error {
	return ad.Del(username)
}

// AdminUpdateUserInfo updates userinfo in underlying USerInfoStorage
func (ad *admin) AdminUpdateUserInfo(userinfo UserInfo) error {
	return ad.Update(userinfo)
}

// AdminUpdateUserPassword updates user's password hash in underlying storage
func (ad *admin) AdminUpdateUserPassword(username, newpassword string) error {
	userinfo, err := ad.Get(username)
	if err != nil {
		return err
	}
	newhash, err := ad.HashPassword(newpassword)
	if err != nil {
		return err
	}
	userinfo.PasswordHash = newhash
	return ad.Update(userinfo)
}
