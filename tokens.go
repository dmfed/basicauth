package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrNoSuchSession = errors.New("error: no such session")

type SessionToken string

type SessionTokenKeeper struct {
	userTokens map[UserName]SessionToken
	mutex      sync.Mutex
}

func NewSessioTokenKeeper() *SessionTokenKeeper {
	var tk SessionTokenKeeper
	tk.userTokens = make(map[UserName]SessionToken)
	return &tk
}

func (tk *SessionTokenKeeper) GenerateSessionToken(user UserName) SessionToken {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write([]byte(time.Now().String()))
	token := SessionToken(fmt.Sprintf("%x", h.Sum(nil)))
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens[user] = token
	// go func{start timer. when expires - remove token from map}()
	return token
}

func (tk *SessionTokenKeeper) UserSessionTokenIsValid(user UserName, token SessionToken) (tokenIsValid bool, err error) {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	validToken, ok := tk.userTokens[user]
	if !ok {
		err = ErrInvalidToken
		return
	}
	if validToken == token {
		tokenIsValid = true
	}
	return
}

func (tk *SessionTokenKeeper) DeleteSessionToken(user UserName) error {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if _, exists := tk.userTokens[user]; exists {
		delete(tk.userTokens, user)
		return nil
	}
	return ErrNoSuchSession
}
