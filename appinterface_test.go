package basicauth_test

import (
	"fmt"
	"testing"

	"github.com/dmfed/basicauth"
	"github.com/dmfed/basicauth/storage"
)

func TestExposedInterface(t *testing.T) {
	st, err := storage.OpenJSONPasswordKeeper("./test.json")
	if err != nil {
		fmt.Println("OpenJSONPasswordKeeper failed", err)
		t.Fail()
	}
	ex, err := basicauth.NewAppInterface(st)
	if err != nil {
		fmt.Println("OpenJSONPasswordKeeper failed", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("dmitry", " hello"); err != nil {
		fmt.Printf("CheckUserPassword for existing user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.AddUser("joe", "passwd"); err != nil {
		fmt.Printf("AddUser for new user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("joe", "passwd"); err != nil {
		fmt.Printf("CheckUserPassword for newly added user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.DelUser("joe", "passwd"); err != nil {
		fmt.Printf("DelUser for newly added user returned: %v\n", err)
		t.Fail()
	}
}
