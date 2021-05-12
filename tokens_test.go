package basicauth

import (
	"fmt"
	"testing"
	"time"
)

func TestTokenGenerator(t *testing.T) {
	fmt.Println("Testing tokens keeper...")
	tk, err := NewMemTokenKeeper(time.Hour)
	if err != nil {
		fmt.Println("NewMemTokenKeeper returned:", err)
		t.Fail()
	}
	tok, err := tk.NewUserToken("test")
	if err != nil {
		fmt.Println("NewUserToken returned:", err)
		t.Fail()
	}
	if currtok, err := tk.GetUserToken("test"); currtok != tok || err != nil {
		fmt.Println("GetUserToken could not fetch existing token:", err)
		t.Fail()
	}
	if _, err := tk.GetUserToken("nonexisting"); err == nil {
		fmt.Println("GetUserToken returned no error for non-existing user")
		t.Fail()
	}
	if err := tk.DelUserToken("nonexisting"); err == nil {
		fmt.Println("DelUserToken returned no error for non-existing user")
		t.Fail()
	}
	if err := tk.DelUserToken("test"); err != nil {
		fmt.Println("DelUserToken returned error for existing user:", err)
		t.Fail()
	}
	if err := tk.DelUserToken("test"); err == nil {
		fmt.Println("DelUserToken returned no error for expired session")
		t.Fail()
	}
}
