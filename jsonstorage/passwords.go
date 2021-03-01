package jsonstorage

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/dmfed/basicauth"
	"golang.org/x/crypto/bcrypt"
)

// JSONPasswordKeeper holds user password hashes in memory
// and saves them to disk on call to Close()
// it implements basicauth.PasswordKeeper interface
type JSONPasswordKeeper struct {
	userSecrets  map[basicauth.UserName]basicauth.Secret
	filename     string
	mutex        sync.Mutex
	stateChanged bool
}

// OpenJSONPasswordKeeper accepts a filename containig usernames and password
// hashes and returns in stance of JSONPasswordKeeper. Function returns an underlying
// error if it fails to read from file or fails to Unmarshal its contents.
func OpenJSONPasswordKeeper(filename string) (basicauth.PasswordKeeper, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return NewJSONPasswordKeeper(filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var pk JSONPasswordKeeper
	pk.userSecrets = make(map[basicauth.UserName]basicauth.Secret)
	if err := json.Unmarshal(data, &pk.userSecrets); err != nil {
		return nil, err
	}
	pk.filename = filename
	return &pk, nil
}

// NewJSONPasswordKeeper creates a new keeper and tries to save to disk.
// Will return underlying error if it fails to Close() (write to designated file)
// properly.
func NewJSONPasswordKeeper(filename string) (basicauth.PasswordKeeper, error) {
	var pk JSONPasswordKeeper
	pk.userSecrets = make(map[basicauth.UserName]basicauth.Secret)
	pk.stateChanged = true
	pk.filename = filename
	return &pk, pk.Close()
}

// CheckUserPassword accepts basicauth.UserName and Password. If password check out with stored hash
// it returns nil. Else will return an error.
func (pk *JSONPasswordKeeper) CheckUserPassword(user basicauth.UserName, password basicauth.Password) (err error) {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	secret, ok := pk.userSecrets[user]
	if !ok {
		return basicauth.ErrNoSuchUser
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secret), []byte(password)); err != nil {
		return basicauth.ErrInvalidPassword
	}
	return nil
}

// AddUser adds new user with requested basicauth.UserName and Password.
func (pk *JSONPasswordKeeper) AddUser(user basicauth.UserName, password basicauth.Password) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userSecrets[user]; exists {
		return basicauth.ErrUserExists
	}
	hashbytes, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		return basicauth.ErrFailedToEncrypt
	}
	secret := basicauth.Secret(hashbytes)
	pk.userSecrets[user] = secret
	pk.stateChanged = true
	return nil
}

// DelUser deletes user with requested basicauth.UserName and Password
func (pk *JSONPasswordKeeper) DelUser(user basicauth.UserName, password basicauth.Password) error {
	if err := pk.CheckUserPassword(user, password); err == nil {
		pk.mutex.Lock()
		defer pk.mutex.Unlock()
		delete(pk.userSecrets, user)
		pk.stateChanged = true
		return nil
	}
	return basicauth.ErrNoSuchUser
}

// ChangeUserPassword changes hash of password stored. Note that this requires both
// existing (old) and new password.
func (pk *JSONPasswordKeeper) ChangeUserPassword(user basicauth.UserName, oldpassword, newpassword basicauth.Password) error {
	if oldpassword == newpassword {
		return basicauth.ErrSamePassword
	}
	if err := pk.CheckUserPassword(user, oldpassword); err == nil {
		pk.mutex.Lock()
		defer pk.mutex.Unlock()
		hashbytes, _ := bcrypt.GenerateFromPassword([]byte(newpassword), 0)
		secret := basicauth.Secret(hashbytes)
		pk.userSecrets[user] = secret
		pk.stateChanged = true
		return nil
	}
	return basicauth.ErrInvalidPassword
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
