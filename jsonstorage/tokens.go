package jsonstorage

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/dmfed/basicauth"
)

// MemSessionTokenKeeper is an in-memory storage of session tokens
// it implements TokenKeeper interface
type MemSessionTokenKeeper struct {
	userTokens  map[basicauth.UserName]basicauth.SessionToken
	maxduration time.Duration
	mutex       sync.Mutex
}

// NewMemSessionTokenKeeper creates new in-memory token keeper
func NewMemSessionTokenKeeper(maxduration time.Duration) (basicauth.TokenKeeper, error) {
	var tk MemSessionTokenKeeper
	tk.userTokens = make(map[basicauth.UserName]basicauth.SessionToken)
	tk.maxduration = maxduration
	return &tk, nil
}

// GenerateToken issues a new token for user valid for specified duration
func (tk *MemSessionTokenKeeper) GenerateToken(user basicauth.UserName) (token basicauth.SessionToken, err error) {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write([]byte(time.Now().String()))
	token = basicauth.SessionToken(fmt.Sprintf("%x", h.Sum(nil)))
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens[user] = token
	go func() {
		timer := time.NewTimer(tk.maxduration)
		<-timer.C
		tk.mutex.Lock()
		defer tk.mutex.Unlock()
		delete(tk.userTokens, user)
	}()
	return token, err
}

// CheckToken verifies token is valid. It returns nil if token is valid or an
// error if token is invalid.
func (tk *MemSessionTokenKeeper) CheckToken(user basicauth.UserName, token basicauth.SessionToken) (err error) {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	validToken, ok := tk.userTokens[user]
	if !ok {
		err = basicauth.ErrNoSuchSession
		return
	}
	if validToken != token {
		err = basicauth.ErrInvalidToken
	}
	return
}

// DeleteUserToken invalidates session token of a cpecified user.
func (tk *MemSessionTokenKeeper) DeleteUserToken(user basicauth.UserName) error {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if _, exists := tk.userTokens[user]; exists {
		delete(tk.userTokens, user)
		return nil
	}
	return basicauth.ErrNoSuchSession
}

// Close is here to comply with TokenKeeper interface
// Tt destroys all tokens on call.
func (tk *MemSessionTokenKeeper) Close() error {
	tk.userTokens = make(map[basicauth.UserName]basicauth.SessionToken)
	return nil
}
