package plainauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrNoSuchUser      = errors.New("error: no such user")
	ErrUserExist       = errors.New("error: user already exists")
	ErrInvalidPassword = errors.New("error: invalid password")
	ErrInvalidToken    = errors.New("error: invalid token")
)

type UserName string
type Secret string
type Password string

func (p Password) Secret() Secret {
	s := fmt.Sprintf("%x", sha256.Sum256([]byte(p)))
	return Secret(s)
}

type PasswordKeeper struct {
	userSecrets  map[UserName]Secret
	filename     string
	mutex        sync.Mutex
	stateChanged bool
}

func NewPasswordKeeper(filename string) (*PasswordKeeper, error) {
	userMap, err := loadUserSecretMapFromFile(filename)
	if err != nil {
		return nil, err
	}
	var pk PasswordKeeper
	pk.userSecrets = userMap
	pk.filename = filename
	return &pk, nil
}

func (pk *PasswordKeeper) UserPasswordIsValid(user UserName, password Password) (passIsValid bool, err error) {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	secret, ok := pk.userSecrets[user]
	if !ok {
		err = ErrNoSuchUser
		return
	}
	if secret == password.Secret() {
		passIsValid = true
	} else {
		err = ErrInvalidPassword
	}
	return
}

func (pk *PasswordKeeper) AddUser(user UserName, password Password) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userSecrets[user]; exists {
		return ErrUserExist
	}
	pk.userSecrets[user] = password.Secret()
	pk.stateChanged = true
	return nil
}

func (pk *PasswordKeeper) DelUser(user UserName) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userSecrets[user]; exists {
		delete(pk.userSecrets, user)
		pk.stateChanged = true
		return nil
	}
	return ErrNoSuchUser
}

func (pk *PasswordKeeper) ChangeUserPassword(user UserName, newpassword Password) error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if _, exists := pk.userSecrets[user]; exists {
		pk.userSecrets[user] = newpassword.Secret()
		pk.stateChanged = true
		return nil
	}
	return ErrNoSuchUser
}

func (pk *PasswordKeeper) Save() error {
	pk.mutex.Lock()
	defer pk.mutex.Unlock()
	if pk.stateChanged {
		return writeUserSecretMapToFile(pk.filename, pk.userSecrets)
	}
	return nil
}
