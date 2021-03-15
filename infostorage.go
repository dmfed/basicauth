package basicauth

import (
	"fmt"
	"time"
)

// UserInfoStorage is required to keep UserInfo
// this can be either local file, a DB or any remote
// storage. basicauth/jsonstorage contains simple implementation
// with JSON file as storage
type UserInfoStorage interface {
	Get(username string) (UserInfo, error)
	Put(UserInfo) error
	Del(username string) error
	Upd(UserInfo) error
	// Close is intended for use in cases when we need to
	// explicitly close network/db connection
	Close() error
}

// UserInfo represent information about user and stores user's
// password hash
type UserInfo struct {
	UserName            string
	PasswordHash        string
	DateCreated         time.Time
	DateChanged         time.Time
	Lastlogin           time.Time
	FailedLoginAttempts int
	MustChangePassword  bool
}

func (u UserInfo) String() string {
	return fmt.Sprintf("username:\t%v\nstored hash:\t%v\ncreated:\t%v\nchanged:\t%v\nlogged on:\t%v\nfailed:\t%v\nmustchange:\t%v\n", u.UserName, u.PasswordHash, u.DateCreated, u.DateChanged, u.Lastlogin, u.FailedLoginAttempts, u.MustChangePassword)
}
