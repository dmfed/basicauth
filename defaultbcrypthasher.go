package basicauth

import (
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 0 // will force bcrypt to use default cost

// PasswordHasher creates hash of pasword and checks
// hashes against passwords
type PasswordHasher interface {
	// CheckUserPassword must return nil if hash and password match
	CheckUserPassword(hash string, password string) error
	// HashPassword takes password as string and returns hash
	HashPassword(password string) (hash string, err error)
}

type defaultBcryptHasher struct{}

func (h *defaultBcryptHasher) HashPassword(password string) (string, error) {
	hashbytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(hashbytes), err
}

func (h *defaultBcryptHasher) CheckUserPassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
