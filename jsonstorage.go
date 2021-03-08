package basicauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	ErrNoSuchUser = errors.New("auth error: no such user")
	ErrUserExists = errors.New("auth error: user already exists")
)

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

// JSONPasswordKeeper holds user password hashes in memory
// and saves them to disk on call to Close()
// it implements UserInfoStorage
type JSONPasswordKeeper struct {
	userInfo map[string]UserInfo
	filename string
	mutex    sync.Mutex
}

// OpenJSONPasswordKeeper accepts a filename containig usernames and password
// hashes and returns in stance of JSONPasswordKeeper. Function returns an underlying
// error if it fails to read from file or fails to Unmarshal its contents.
func OpenJSONPasswordKeeper(filename string) (UserInfoStorage, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return NewJSONPasswordKeeper(filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var pk JSONPasswordKeeper
	pk.userInfo = make(map[string]UserInfo)
	if err := json.Unmarshal(data, &pk.userInfo); err != nil {
		return nil, err
	}
	pk.filename = filename
	return &pk, nil
}

// NewJSONPasswordKeeper creates a new keeper and tries to save to disk.
// Will return underlying error if it fails to write to designated file)
// properly.
func NewJSONPasswordKeeper(filename string) (UserInfoStorage, error) {
	if filename == "" {
		return nil, fmt.Errorf("empty filename provided. will do nothing")
	}
	if _, err := os.Stat(filename); err == nil {
		return nil, fmt.Errorf("error: file %v already exists", filename)
	}
	var pk JSONPasswordKeeper
	pk.userInfo = make(map[string]UserInfo)
	pk.filename = filename
	return &pk, pk.flushToDisk()
}

// Put adds UseerInfo to storage
func (pk *JSONPasswordKeeper) Put(userinfo UserInfo) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userInfo[userinfo.UserName]; exists {
		return ErrUserExists
	}
	pk.userInfo[userinfo.UserName] = userinfo
	return pk.flushToDisk()
}

// Get returns UserInfo if username is valid
func (pk *JSONPasswordKeeper) Get(username string) (UserInfo, error) {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	userinfo, exists := pk.userInfo[username]
	if !exists {
		return UserInfo{}, ErrNoSuchUser
	}
	return userinfo, nil
}

// Del deletes UserInfo is username is valid
func (pk *JSONPasswordKeeper) Del(username string) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userInfo[username]; exists {
		delete(pk.userInfo, username)
		return pk.flushToDisk()
	}
	return ErrNoSuchUser
}

// Update finds if user with UserName as in supplied userinfo exists and
// updates existing info for that user with supplied userinfo.
func (pk *JSONPasswordKeeper) Update(userinfo UserInfo) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, ok := pk.userInfo[userinfo.UserName]; ok {
		pk.userInfo[userinfo.UserName] = userinfo
		return pk.flushToDisk()
	}
	return ErrNoSuchUser
}

func (pk *JSONPasswordKeeper) flushToDisk() error {
	// This method is always called from functions which
	// defer pk.mutex.Unlock() so no need to use mutex here,
	// we're protected already.
	data, err := json.MarshalIndent(pk.userInfo, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(pk.filename, data, 0600)
}
