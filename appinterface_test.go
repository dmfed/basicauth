package basicauth_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/dmfed/basicauth"
	"github.com/dmfed/basicauth/storage"
)

func TestExposedInterface(t *testing.T) {
	filename := "./test.json"
	st, err := storage.NewJSONPasswordKeeper(filename)
	if err != nil {
		fmt.Println("NewJSONPasswordKeeper failed", err)
		t.Fail()
	}
	ex, err := basicauth.NewAppInterface(st)
	if err != nil {
		fmt.Println("NewAppInterface failed", err)
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
	if err := ex.ChangeUserPassword("joe", "passwd", "newpasswd"); err != nil {
		fmt.Printf("ChangeUserPassword for newly added user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("joe", "passwd"); err == nil {
		fmt.Println("CheckUserPassword returned nil for invalid password")
		t.Fail()
	}
	if _, err := ex.GetUserInfo("joe", "passwd"); err == nil {
		fmt.Println("GetUserInfo returned nil with invalid password")
		t.Fail()
	}
	if ui, err := ex.GetUserInfo("joe", "newpasswd"); (err != nil || ui != basicauth.UserInfo{}) {
		fmt.Println("GetUserInfo returned non-empty UserInfo")
		t.Fail()
	}
	if err := ex.DelUser("joe", "newpasswd"); err != nil {
		fmt.Printf("DelUser for newly added user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("joe", "passwd"); err == nil {
		fmt.Println("CheckUserPassword for deleted user returned nil")
		t.Fail()
	}
	st.Close()
	os.Remove(filename)
}
