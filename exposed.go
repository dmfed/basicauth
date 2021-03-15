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
	// ErrMustChangePassword is returned when newly created user tries to login with default pass
	ErrMustChangePassword = fmt.Errorf("default password \"%v\" is set for user. change password to be able to login. use \"%v\" as current password", defaultPassword, defaultPassword)
)

// ExposedInterface is an interface intended to be exposed to outside world / client application
// It requires current user password for any interaction.
// It can only add/change/delete userinfo. For keepeing login sessions see
// LoginManager interface
type ExposedInterface interface {
	CheckUserPassword(username string, password string) error
	AddUser(username string, password string) error
	ChangeUserPassword(username string, oldpassword string, newpassword string) error
	DelUser(username string, password string) error
	GetUserInfo(username, password string) (UserInfo, error)
	UpdateUserInfo(username, password string, newinfo UserInfo) error
}

// Exposed holds ExposedInterface
type exposed struct {
	st  UserInfoStorage
	hsr PasswordHasher
}

// NewExposedInterface creates instnce of Exposed
func NewExposedInterface(st UserInfoStorage) (ExposedInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &exposed{st, globalHasher}, nil
}

// CheckUserPassword fetches UserInfo from underlying UserInfoStorage and uses
// package default hasher to compare provided password with stored hash.
// Returns nil is password checks out else error.
// If fetch from starage fails returns underlying error.
func (ex *exposed) CheckUserPassword(username string, password string) error {
	userinfo, err := ex.st.Get(username)
	if err != nil {
		return err
	}
	if userinfo.MustChangePassword {
		return ErrMustChangePassword
	}
	if err := ex.hsr.CheckUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	userinfo.Lastlogin = time.Now()
	return ex.st.Upd(userinfo)
}

// AddUser adds new UserInfo to underlying IserInfoStorage.
func (ex *exposed) AddUser(username string, password string) error {
	_, err := ex.st.Get(username)
	if err == nil {
		return ErrUserExists
	}
	hash, err := ex.hsr.HashPassword(password)
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
	return ex.st.Put(userinfo)
}

// DelUser deletes UserInfo with UserName == username from underlying
// UserInfoStorage.
func (ex *exposed) DelUser(username string, password string) error {
	userinfo, err := ex.st.Get(username)
	if err != nil {
		return err
	}
	if err := ex.hsr.CheckUserPassword(userinfo.PasswordHash, password); err != nil {
		return err
	}
	return ex.st.Del(username)
}

// ChangeUserPassword fetches UserInfo for username from storage, verifies user current password,
// hashes new password and updates UserInfo in underlying storage.
func (ex *exposed) ChangeUserPassword(username string, oldpassword string, newpassword string) error {
	if oldpassword == newpassword {
		return ErrSamePassword
	}
	userinfo, err := ex.st.Get(username)
	if err != nil {
		return err
	}
	if err := ex.hsr.CheckUserPassword(userinfo.PasswordHash, oldpassword); err != nil {
		return err
	}
	hash, err := ex.hsr.HashPassword(newpassword)
	if err != nil {
		return err
	}
	userinfo.PasswordHash = hash
	userinfo.DateChanged = time.Now()
	return ex.st.Upd(userinfo)
}

func (ex *exposed) GetUserInfo(username, password string) (userinfo UserInfo, err error) {
	userinfo, err = ex.st.Get(username)
	if err != nil {
		return
	}
	if err := ex.hsr.CheckUserPassword(userinfo.PasswordHash, password); err != nil {
		return UserInfo{}, ErrInvalidPassword
	}
	return
}

func (ex *exposed) UpdateUserInfo(username, password string, newinfo UserInfo) error {
	userinfo, err := ex.st.Get(username)
	if err != nil {
		return err
	}
	if err := ex.hsr.CheckUserPassword(userinfo.PasswordHash, password); err != nil {
		return ErrInvalidPassword
	}
	// Doing nothing at this point. If UserInfo gets more fields - this method will be a must
	return nil
}
