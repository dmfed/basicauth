package memtokens

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
	userTokens  map[string]string
	maxduration time.Duration
	mutex       sync.Mutex
}

// NewMemSessionTokenKeeper creates new in-memory token keeper
func NewMemSessionTokenKeeper(maxduration time.Duration) (basicauth.TokenKeeper, error) {
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
		err = basicauth.ErrNoSuchSession
		return
	}
	if validToken != token {
		err = basicauth.ErrInvalidToken
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
	return basicauth.ErrNoSuchSession
}

// destroys all tokens on call.
func (tk *MemSessionTokenKeeper) clear() {
	tk.mutex.Lock()
	defer tk.mutex.Unlock()
	tk.userTokens = make(map[string]string)
}
