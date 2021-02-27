package basicauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoSuchSession     = errors.New("error: no such session")
	ErrInvalidToken      = errors.New("error: invalid token")
	ErrIncorrectDuration = errors.New("error: token duration invalid")
)

// MemSessionTokenKeeper is an in-memory storage of session tokens
type MemSessionTokenKeeper struct {
	userTokens  map[UserName]SessionToken
	maxduration time.Duration
	mutex       sync.Mutex
}

// NewMemSessionTokenKeeper creates new in-memory token keeper
func NewMemSessionTokenKeeper(maxduration time.Duration) (*MemSessionTokenKeeper, error) {
	var tk MemSessionTokenKeeper
	tk.userTokens = make(map[UserName]SessionToken)
	tk.maxduration = maxduration
	return &tk, nil
}

// GenerateToken issues a new token for user valid for specified duration
func (tk *MemSessionTokenKeeper) GenerateToken(user UserName) (token SessionToken, err error) {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write([]byte(time.Now().String()))
	token = SessionToken(fmt.Sprintf("%x", h.Sum(nil)))
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
func (tk *MemSessionTokenKeeper) CheckToken(user UserName, token SessionToken) (err error) {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	validToken, ok := tk.userTokens[user]
	if !ok {
		err = ErrNoSuchSession
		return
	}
	if validToken != token {
		err = ErrInvalidToken
	}
	return
}

// DeleteUserSession invalidates session token of a cpecified user.
func (tk *MemSessionTokenKeeper) DeleteUserSession(user UserName) error {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if _, exists := tk.userTokens[user]; exists {
		delete(tk.userTokens, user)
		return nil
	}
	return ErrNoSuchSession
}

// Close is here to comply with TokenKeeper interface
// Tt destroys all tokens on call.
func (tk *MemSessionTokenKeeper) Close() error {
	tk.userTokens = make(map[UserName]SessionToken)
	return nil
}
