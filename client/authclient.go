package client

import "github.com/dmfed/basicauth"

type AuthClient struct {
	ipAddr      string
	masterToken string
}

func New(ip, port, mastertoken string, secure bool) (basicauth.Authenticator, error) {
	var ac AuthClient
	ac.ipAddr = ip + ":" + port
	ac.masterToken = mastertoken
	return nil, nil
}

func (ac *AuthClient) CheckUserPassword(basicauth.UserName, basicauth.Password) error {
	return nil
}

func (ac *AuthClient) AddUser(basicauth.UserName, basicauth.Password) error {
	return nil
}

func (ac *AuthClient) DelUser(basicauth.UserName, basicauth.Password) error {
	return nil
}

func (ac *AuthClient) ChangeUserPassword(basicauth.UserName, basicauth.Password, basicauth.Password) error {
	return nil
}

func (ac *AuthClient) Close() error {
	return nil
}

func (ac *AuthClient) GenerateToken(basicauth.UserName) (basicauth.SessionToken, error) {
	return basicauth.SessionToken(""), nil
}

func (ac *AuthClient) CheckToken(basicauth.UserName, basicauth.SessionToken) error {
	return nil
}

func (ac *AuthClient) DeleteUserSession(basicauth.UserName) error {
	return nil
}
