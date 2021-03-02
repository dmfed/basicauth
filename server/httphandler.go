package server

import (
	"net/http"

	"github.com/dmfed/basicauth"
)

type HTTPHandler struct {
	PasswordKeeper basicauth.UserManager
	TokenKeeper    basicauth.TokenKeeper
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Server is running and accepting connections"))
}

/*
func JSONBytesToRequest(data []byte) (Request, error) {
	return Request{}, nil
}

func ResponseToJSONBytes(resp Response) ([]byte, error) {
	return []byte{}, nil
}

func ProcessPasswordRequest(req Request, pk PasswordKeeper) Response {

}

func ProcessTokenRequest(req Request, tk TokenKeeper) Response {

}

func AuthRequestToHTTP(Request) *http.Request {

} */

/* // Request is a representation of JSON request to the server.
// If sent with GET method will try to verify Username and string.
// With PUT will add new user. With POST will try to update string.
// If sent with DEL will try to delete user.
type Request struct {
	// Action should be one of: "adduser", "deluser",
	// "checkstring", "changeuserstring", "generatetoken",
	// "checktoken", "deleteusersession"
	Action      string       `json:"action"`
	Username    string     `json:"username"`
	string    string     `json:"password,omitempty"`
	OldPassword string     `json:"oldpassword,omitempty"`
	Token       string `json:"token,omitempty"`
}

// Response represents response from server
type Response struct {
	OK    bool         `json:"ok"`
	Token string `json:"token,omitempty"`
	Error string       `json:"error"`
}
*/
