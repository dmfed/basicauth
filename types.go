package basicauth

import (
	"time"
)

// UserInfo represent information about user
type UserInfo struct {
	UserName            string
	PasswordHash        string
	DateRegistered      time.Time
	Lastlogin           time.Time
	FailedLoginAttempts int
}

// UserInfoStorage is required to keep UserInfo
// this can be either local file, a DB or any remote
// storage. basicauth/jsonstorage contains simple implementation
// with JSON file as storage
type UserInfoStorage interface {
	Get(username string) (UserInfo, error)
	Put(UserInfo) error
	Del(username string) error
	Update(UserInfo) error
}
