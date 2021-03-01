package jsonstorage

import (
	"fmt"
	"testing"

	"github.com/dmfed/basicauth"
)

// Some very basic tests for now

func Test_JSON_PasswordHashesAndChecksOut(t *testing.T) {
	pk := new(JSONPasswordKeeper)
	pk.userSecrets = make(map[basicauth.UserName]basicauth.Secret)
	user, password := basicauth.UserName("dmitry"), basicauth.Password("hello")
	pk.AddUser(user, password)
	if err := pk.CheckUserPassword(user, password); err != nil {
		fmt.Printf("error: correct password didn't check out %v\n", err)
		t.Fail()
	}
	if err := pk.CheckUserPassword(user, basicauth.Password("hello1")); err == nil {
		fmt.Printf("error: incorrect password checks out %v\n", err)
		t.Fail()
	}
}

func Test_JSON_PasswordKeeperAddsAndDeletesUser(t *testing.T) {
	pk := new(JSONPasswordKeeper)
	pk.userSecrets = make(map[basicauth.UserName]basicauth.Secret)
	user, password := basicauth.UserName("dmitry"), basicauth.Password("hello")
	pk.AddUser(user, password)
	if err := pk.CheckUserPassword(user, password); err != nil {
		fmt.Println("failed to add user")
		t.Fail()
	}
	if err := pk.DelUser(user, password); err != nil {
		fmt.Println(err)
		t.Fail()
	}
	if err := pk.CheckUserPassword(user, password); err == nil {
		fmt.Println("failed to delete user")
		t.Fail()
	}
}

func Test_NewPasswordKeeper(t *testing.T) {
	pk, err := NewJSONPasswordKeeper("test.json")
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	user, password := basicauth.UserName("dmitry"), basicauth.Password("hello")
	if err := pk.AddUser(user, password); err != nil {
		fmt.Println(err)
		t.Fail()
	}
	if err := pk.Close(); err != nil {
		fmt.Println(err)
		t.Fail()
	}
}

func Test_OpenPasswordKeeper(t *testing.T) {
	pk, err := OpenJSONPasswordKeeper("test.json")
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	user, password := basicauth.UserName("dmitry"), basicauth.Password("hello")
	if err := pk.CheckUserPassword(user, password); err != nil {
		t.Fail()
	}
}
