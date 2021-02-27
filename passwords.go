package basicauth

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoSuchUser      = errors.New("error: no such user")
	ErrUserExist       = errors.New("error: user already exists")
	ErrInvalidPassword = errors.New("error: invalid password")
)

// JSONPasswordKeeper holds user password hashes in memory
// and saves them to disk on call to Close()
type JSONPasswordKeeper struct {
	userSecrets  map[UserName]Secret
	filename     string
	mutex        sync.Mutex
	stateChanged bool
}

// OpenJSONPasswordKeeper accepts a filename containig usernames and password
// hashes and returns in stance of JSONPasswordKeeper. Function returns an underlying
// error if it fails to read from file or fails to Unmarshal its contents.
func OpenJSONPasswordKeeper(filename string) (*JSONPasswordKeeper, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return NewJSONPasswordKeeper(filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var pk JSONPasswordKeeper
	pk.userSecrets = make(map[UserName]Secret)
	if err := json.Unmarshal(data, &pk.userSecrets); err != nil {
		return nil, err
	}
	pk.filename = filename
	return &pk, nil
}

// NewJSONPasswordKeeper creates a new keeper and tries to save to disk.
// Will return underlying error if it fails to Close() (write to designated file)
// properly.
func NewJSONPasswordKeeper(filename string) (*JSONPasswordKeeper, error) {
	var pk JSONPasswordKeeper
	pk.userSecrets = make(map[UserName]Secret)
	pk.stateChanged = true
	pk.filename = filename
	return &pk, pk.Close()
}

// CheckUserPassword accepts UserName and Password. If password check out with stored hash
// it returns nil. Else will return an error.
func (pk *JSONPasswordKeeper) CheckUserPassword(user UserName, password Password) (err error) {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	secret, ok := pk.userSecrets[user]
	if !ok {
		return ErrNoSuchUser
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secret), []byte(password)); err != nil {
		return ErrInvalidPassword
	}
	return nil
}

// AddUser adds new user with requested UserName and Password.
func (pk *JSONPasswordKeeper) AddUser(user UserName, password Password) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userSecrets[user]; exists {
		return ErrUserExist
	}
	hashbytes, _ := bcrypt.GenerateFromPassword([]byte(password), 0)
	secret := Secret(hashbytes)
	pk.userSecrets[user] = secret
	pk.stateChanged = true
	return nil
}

// DelUser deletes user with requested UserName and Password
func (pk *JSONPasswordKeeper) DelUser(user UserName, password Password) error {
	if err := pk.CheckUserPassword(user, password); err == nil {
		pk.mutex.Lock()
		defer pk.mutex.Unlock()
		delete(pk.userSecrets, user)
		pk.stateChanged = true
		return nil
	}
	return ErrNoSuchUser
}

// ChangeUserPassword changes hash of password stored. Note that this requires both
// existing (old) and new password.
func (pk *JSONPasswordKeeper) ChangeUserPassword(user UserName, oldpassword, newpassword Password) error {
	if err := pk.CheckUserPassword(user, oldpassword); err == nil {
		pk.mutex.Lock()
		defer pk.mutex.Unlock()
		hashbytes, _ := bcrypt.GenerateFromPassword([]byte(newpassword), 0)
		secret := Secret(hashbytes)
		pk.userSecrets[user] = secret
		pk.stateChanged = true
		return nil
	}
	return ErrNoSuchUser
}

// Close writes all user passwords back to file.
func (pk *JSONPasswordKeeper) Close() error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if pk.stateChanged {
		data, err := json.MarshalIndent(pk.userSecrets, "", "    ")
		if err != nil {
			return err
		}
		return os.WriteFile(pk.filename, data, 0600)
	}
	return nil
}
