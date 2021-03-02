package tokens

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoSuchSession = errors.New("auth error: user is not logged in")
	ErrInvalidToken  = errors.New("auth error: invalid token")
)

// TokenKeeper is an interface to whatever token storage we have
type TokenKeeper interface {
	GenerateToken(username string) (token string, err error)
	CheckToken(username string, token string) error
	DeleteUserToken(username string) error
}

// MemSessionTokenKeeper is an in-memory storage of session tokens
// it implements TokenKeeper interface
type MemSessionTokenKeeper struct {
	userTokens  map[string]string
	maxduration time.Duration
	mutex       sync.Mutex
}

// NewMemSessionTokenKeeper creates new in-memory token keeper
func NewMemSessionTokenKeeper(maxduration time.Duration) (TokenKeeper, error) {
	var tk MemSessionTokenKeeper
	tk.userTokens = make(map[string]string)
	tk.maxduration = maxduration
	return &tk, nil
}

// GenerateToken issues a new token for user valid for specified duration
func (tk *MemSessionTokenKeeper) GenerateToken(username string) (token string, err error) {
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(time.Now().String()))
	token = string(fmt.Sprintf("%x", h.Sum(nil)))
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens[username] = token
	go func() {
		timer := time.NewTimer(tk.maxduration)
		<-timer.C
		tk.mutex.Lock()
		defer tk.mutex.Unlock()
		delete(tk.userTokens, username)
	}()
	return token, err
}

// CheckToken verifies token is valid. It returns nil if token is valid or an
// error if token is invalid.
func (tk *MemSessionTokenKeeper) CheckToken(username string, token string) (err error) {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	validToken, ok := tk.userTokens[username]
	if !ok {
		err = ErrNoSuchSession
		return
	}
	if validToken != token {
		err = ErrInvalidToken
	}
	return
}

// DeleteUserToken invalidates session token of a cpecified user.
func (tk *MemSessionTokenKeeper) DeleteUserToken(user string) error {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if _, exists := tk.userTokens[user]; exists {
		delete(tk.userTokens, user)
		return nil
	}
	return ErrNoSuchSession
}

// destroys all tokens on call.
func (tk *MemSessionTokenKeeper) clear() {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens = make(map[string]string)
}
