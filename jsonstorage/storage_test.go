package jsonstorage

import (
	"fmt"
	"os"
	"testing"

	"github.com/dmfed/basicauth"
)

var (
	testUser        = "jimi"
	testInvalidUser = "jamie"
	testHash        = "xxxxFFFFgggg$"
	testUserInfo    = basicauth.UserInfo{UserName: testUser, PasswordHash: testHash}
	testFileName    = "test.json"
)

var sampleContent = []byte(fmt.Sprintf(`{
    "%s": {
        "UserName": "%s",
        "PasswordHash": "%s",
        "DateCreated": "2021-03-08T02:26:57.081387+03:00",
        "DateChanged": "2021-03-08T02:26:57.081387+03:00",
        "Lastlogin": "0001-01-01T00:00:00Z",
        "FailedLoginAttempts": 0,
        "MustChangePassword": false
    }
}`, testUser, testUser, testHash))

func init() {
	if _, err := os.Stat(testFileName); err == nil {
		os.Remove(testFileName)
	}
}

func Test_NewJSONPAsswordKeeper(t *testing.T) {
	fmt.Println("Testing NewJSONPasswordKeeper")
	pk, err := NewJSONPasswordKeeper(testFileName)
	if err != nil {
		fmt.Printf("NewJSONPasswordKeeper('test.json') failed with error: %v\n", err)
		t.Fail()
	}
	if err = pk.Put(testUserInfo); err != nil {
		fmt.Println("failed to Put() test user info")
		t.Fail()
	}
	if err = pk.Put(testUserInfo); err == nil {
		fmt.Println("Put() with existing user does not produce error")
		t.Fail()
	}
	uinfo, err := pk.Get(testUser)
	if err != nil {
		fmt.Println("failed to Get() userinfo for existing user")
		t.Fail()
	}
	if _, err := pk.Get(testInvalidUser); err == nil {
		fmt.Println("Get() invalid user produces no errors")
	}
	if uinfo != testUserInfo {
		fmt.Println("userinfo received with Get() does not match, want:", testUserInfo, "got:", uinfo)
		t.Fail()
	}
	uinfo.PasswordHash = "newhash"
	if err = pk.Update(uinfo); err != nil {
		fmt.Println("failed to Update() userinfo", err)
		t.Fail()
	}
	newuinfo, err := pk.Get(testUser)
	if uinfo != newuinfo {
		fmt.Println("updated userinfo does not match, want:", uinfo, "got:", newuinfo)
		t.Fail()
	}
	if err = pk.Del(testUser); err != nil {
		fmt.Println("failed to Del() test user", err)
		t.Fail()
	}
	if _, err = pk.Get(testUser); err == nil {
		fmt.Println("user still exists after Del()", err)
		t.Fail()
	}
	os.Remove(testFileName)
}

func Test_OpenJSONPasswordKeeper(t *testing.T) {
	fmt.Println("Testing OpenJSONPasswordKeeper")
	os.WriteFile(testFileName, sampleContent, 0644)
	pk, err := OpenJSONPasswordKeeper(testFileName)
	if err != nil {
		fmt.Printf("OpenJSONPasswordKeeper('test.json') failed with error: %v\n", err)
		t.Fail()
	}
	userinfo, err := pk.Get(testUser)
	if err != nil {
		fmt.Println("failed to Get() existing user")
		t.Fail()
	}
	if userinfo.UserName != testUser {
		fmt.Println("received userinfo does not match want:", testUser, "got:", userinfo.UserName)
		t.Fail()
	}
	if userinfo.PasswordHash != testHash {
		fmt.Println("received userinfo does not match want:", testHash, "got", userinfo.PasswordHash)
		t.Fail()
	}
	os.Remove(testFileName)
}
