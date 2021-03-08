package jsonstorage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/dmfed/basicauth"
)

var (
	ErrNoSuchUser = errors.New("auth error: no such user")
	ErrUserExists = errors.New("auth error: user already exists")
)

// JSONPasswordKeeper holds user password hashes in memory
// and saves them to disk on call to Close()
// it implements basicauth.UserInfoStorage
type JSONPasswordKeeper struct {
	userInfo map[string]basicauth.UserInfo
	filename string
	mutex    sync.Mutex
}

// OpenJSONPasswordKeeper accepts a filename containig usernames and password
// hashes and returns in stance of JSONPasswordKeeper. Function returns an underlying
// error if it fails to read from file or fails to Unmarshal its contents.
func OpenJSONPasswordKeeper(filename string) (basicauth.UserInfoStorage, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return NewJSONPasswordKeeper(filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var pk JSONPasswordKeeper
	pk.userInfo = make(map[string]basicauth.UserInfo)
	if err := json.Unmarshal(data, &pk.userInfo); err != nil {
		return nil, err
	}
	pk.filename = filename
	return &pk, nil
}

// NewJSONPasswordKeeper creates a new keeper and tries to save to disk.
// Will return underlying error if it fails to write to designated file)
// properly.
func NewJSONPasswordKeeper(filename string) (basicauth.UserInfoStorage, error) {
	if filename == "" {
		return nil, fmt.Errorf("empty filename provided. will do nothing")
	}
	if _, err := os.Stat(filename); err == nil {
		return nil, fmt.Errorf("error: file %v already exists", filename)
	}
	var pk JSONPasswordKeeper
	pk.userInfo = make(map[string]basicauth.UserInfo)
	pk.filename = filename
	return &pk, pk.flushToDisk()
}

// Put adds UseerInfo to storage
func (pk *JSONPasswordKeeper) Put(userinfo basicauth.UserInfo) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userInfo[userinfo.UserName]; exists {
		return ErrUserExists
	}
	pk.userInfo[userinfo.UserName] = userinfo
	return pk.flushToDisk()
}

// Get returns UserInfo if username is valid
func (pk *JSONPasswordKeeper) Get(username string) (basicauth.UserInfo, error) {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	userinfo, exists := pk.userInfo[username]
	if !exists {
		return basicauth.UserInfo{}, ErrNoSuchUser
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
func (pk *JSONPasswordKeeper) Update(userinfo basicauth.UserInfo) error {
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
