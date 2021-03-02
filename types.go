package basicauth

import (
	"errors"
	"time"
)

var (
	ErrNoSuchUser      = errors.New("auth error: no such user")
	ErrUserExists      = errors.New("auth error: user already exists")
	ErrInvalidPassword = errors.New("auth error: password does not check out with stored value")
	ErrFailedToEncrypt = errors.New("auth error: could not hash provided password")
	ErrSamePassword    = errors.New("auth error: old password and new password must not match")
	ErrNoSuchSession   = errors.New("auth error: user is not logged in")
	ErrInvalidToken    = errors.New("auth error: invalid token")
)

// UserInfo represent information about user
type UserInfo struct {
	UserName            string
	PasswordHash        string
	PasswordHint        string
	DateRegistered      time.Time
	Lastlogin           time.Time
	FailedLoginAttempts int
}

// UserInfoStorage is required to keep UserInfo
// this can be either local file, a DB or any remote
// storage
type UserInfoStorage interface {
	Put(UserInfo) error
	Get(username string) (UserInfo, error)
	Del(username string) error
}

// PasswordChecker takes username and password, builds hash of
// password and compares it to available hash
type PasswordChecker interface {
	CheckUserPassword(hash string, password string) error
}

// PasswordHasher creates hash of pasword
type PasswordHasher interface {
	HashPassword(password string) (hash string, err error)
}

// UserManager allows to add and remove users, or change user password
type UserManager interface {
	AddUser(username string, password string) error
	DelUser(username string, password string) error
	ChangeUserPassword(username string, oldpassword string, newpassword string) error
	GetUserInfo(username string)
}

// TokenKeeper is an interface to whatever token storage we have
type TokenKeeper interface {
	GenerateToken(username string) (token string, err error)
	CheckToken(username string, token string) error
	DeleteUserToken(username string) error
}
