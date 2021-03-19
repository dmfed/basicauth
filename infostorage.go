package basicauth

import (
	"fmt"
	"time"
)

// UserInfoStorage is required to keep UserInfo
// this can be either local file, a DB or any remote
// storage. basicauth/jsonstorage contains simple implementation
// with JSON file as storage
type UserAccountStorage interface {
	Get(username string) (Account, error)
	Put(Account) error
	Del(username string) error
	Upd(Account) error
	// Close is intended for use in cases when we need to
	// explicitly close network/db connection
	Close() error
}

// UserInfo represent information about user and stores user's
// password hash
type UserInfo struct {
	Name       string `json:",omitempty"`
	Middlename string `json:",omitempty"`
	Lastname   string `json:",omitempty"`
	Comment    string `json:",omitempty"`
	// ... add fileds as necessary
}

func (u UserInfo) String() string {
	out := "Name: " + u.Name
	if u.Middlename != "" {
		out += " " + u.Middlename
	}
	out += " " + u.Lastname
	return out
}

type Account struct {
	UserName            string
	PasswordHash        string
	DateCreated         time.Time `json:",omitempty"`
	DateChanged         time.Time `json:",omitempty"`
	Lastlogin           time.Time `json:",omitempty"`
	FailedLoginAttempts int       `json:",omitempty"`
	MustChangePassword  bool      `json:",omitempty"`
	User                UserInfo  `json:",omitempty"`
}

func (acc Account) String() string {
	out := fmt.Sprintf("username: %v\npwdhash: %v\ncreated: %v\nchanged: %v\nlogin: %v\nfailed: %v\nmustchange: %v\ninfo:\n%v",
		acc.UserName, acc.PasswordHash, acc.DateCreated, acc.DateChanged, acc.Lastlogin, acc.FailedLoginAttempts, acc.MustChangePassword, acc.User)
	return out
}
