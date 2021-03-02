package basicauth

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	hashbytes, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	return string(hashbytes), err
}

func CheckUserPassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
