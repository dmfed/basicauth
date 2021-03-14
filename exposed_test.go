package basicauth

import (
	"fmt"
	"testing"
)

func TestExposedInterface(t *testing.T) {
	st, err := OpenJSONPasswordKeeper("./test.json")
	if err != nil {
		fmt.Println("OpenJSONPasswordKeeper failed", err)
		t.Fail()
	}
	ex, err := NewExposedInterface(st)
	if err != nil {
		fmt.Println("OpenJSONPasswordKeeper failed", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("dmitry", " hello"); err != nil {
		fmt.Printf("CheckUserPassword for existing user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.AddUser("dmitry", " hello"); err != nil {
		fmt.Printf("AddUser for new user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.CheckUserPassword("dmitry", " hello"); err != nil {
		fmt.Printf("CheckUserPassword for newly added user returned: %v\n", err)
		t.Fail()
	}
	if err := ex.AddUser("joe", "passwd"); err != nil {
		fmt.Printf("DelUser for newly added user returned: %v\n", err)
		t.Fail()
	}
}
