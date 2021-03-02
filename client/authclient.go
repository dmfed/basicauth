package client

type AuthClient struct {
	ipAddr      string
	masterToken string
}

func New(ip, port, mastertoken string, secure bool) (string, error) {
	var ac AuthClient
	ac.ipAddr = ip + ":" + port
	ac.masterToken = mastertoken
	return "", nil
}

func (ac *AuthClient) CheckUserPassword(string, string) error {
	return nil
}

func (ac *AuthClient) AddUser(string, string) error {
	return nil
}

func (ac *AuthClient) DelUser(string, string) error {
	return nil
}

func (ac *AuthClient) ChangeUserPassword(string, string, string) error {
	return nil
}

func (ac *AuthClient) Close() error {
	return nil
}

func (ac *AuthClient) GenerateToken(string) (string, error) {
	return "", nil
}

func (ac *AuthClient) CheckToken(string, string) error {
	return nil
}

func (ac *AuthClient) DeleteUserSession(string) error {
	return nil
}
