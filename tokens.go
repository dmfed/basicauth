package basicauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrNoSuchSession is returned when user is not logged in
	ErrNoSuchSession = errors.New("auth error: user is not logged in")
	// ErrInvalidToken is returned when token does not check out
	ErrInvalidToken = errors.New("auth error: invalid token")
)

// TokenKeeper is an interface to whatever token storage we have
type TokenKeeper interface {
	NewUserToken(username string) (token string, err error)
	GetUserToken(username string) (token string, err error)
	DelUserToken(username string) error
}

// MemSessionTokenKeeper is an in-memory storage of session tokens
// it implements TokenKeeper interface
type memSessionTokenKeeper struct {
	userTokens  map[string]string
	maxduration time.Duration
	mutex       sync.Mutex
}

// NewMemSessionTokenKeeper creates new in-memory token keeper
func NewMemTokenKeeper(sessionduration time.Duration) (TokenKeeper, error) {
	var tk memSessionTokenKeeper
	tk.userTokens = make(map[string]string)
	tk.maxduration = sessionduration
	return &tk, nil
}

// GenerateToken issues a new token for user valid for specified duration
func (tk *memSessionTokenKeeper) NewUserToken(username string) (token string, err error) {
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

// DeleteUserToken invalidates session token of a cpecified user.
func (tk *memSessionTokenKeeper) DelUserToken(username string) error {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if _, exists := tk.userTokens[username]; exists {
		delete(tk.userTokens, username)
		return nil
	}
	return ErrNoSuchSession
}

func (tk *memSessionTokenKeeper) GetUserToken(username string) (token string, err error) {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	if token, exists := tk.userTokens[username]; exists {
		return token, nil
	}
	return "", ErrNoSuchSession
}

// Clear destroys all tokens in single call.
func (tk *memSessionTokenKeeper) Clear() {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens = make(map[string]string)
}
