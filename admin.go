package basicauth

import "fmt"

type AdminInterface interface {
	AdminAddUser(username string, password string) error //Change to return random password
	AdminDelUser(username string) error
	AdminGetUserInfo(username string) (UserInfo, error)
	AdminUpdateUserInfo(UserInfo) error
}

type Admin struct {
	Storage UserInfoStorage
}

func NewAdmin(st UserInfoStorage) (AdminInterface, error) {
	if st == nil {
		return nil, fmt.Errorf("error: storage is nil")
	}
	return &Admin{st}, nil
}

func (ad *Admin) GetAdminInterface() AdminInterface {
	return ad
}

func (ad *Admin) AdminGetUserInfo(username string) (UserInfo, error) {
	return ad.Storage.Get(username)
}

func (ad *Admin) AdminAddUser(username string, password string) error {
	return ad.Storage.Put(UserInfo{}) // TODO
}

func (ad *Admin) AdminDelUser(username string) error {
	return ad.Storage.Del(username)
}

func (ad *Admin) AdminUpdateUserInfo(userinfo UserInfo) error {
	return ad.Storage.Update(userinfo)
}
