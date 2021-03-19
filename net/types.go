package net

import (
	"encoding/json"

	"github.com/dmfed/basicauth"
)

// Request represents request to auth server
type Request struct {
	ID          string             `json:",omitempty"`
	Action      string             `json:",omitempty"`
	Token       string             `json:",omitempty"`
	UserName    string             `json:",omitempty"`
	Password    string             `json:",omitempty"`
	NewPassword string             `json:",omitempty"`
	UserInfo    basicauth.UserInfo `json:",omitempty"`
	Account     basicauth.Account  `json:",omitempty"`
}

// Response represents response of auth server
type Response struct {
	ID       string             `json:",omitempty"`
	OK       bool               `json:",omitempty"`
	Error    string             `json:",omitempty"`
	Token    string             `json:",omitempty"`
	UserInfo basicauth.UserInfo `json:",omitempty"`
	Account  basicauth.Account  `json:",omitempty"`
}

// Message type is a basic transfer unit for Requests and Responses
type Message struct {
	ID       string   `json:",omitempty"`
	AppToken string   `json:",omitempty"`
	Request  Request  `json:",omitempty"`
	Response Response `json:",omitempty"`
}

// Bytes encodes Message to JSON and returns []byte which can be
// written to http.ResponseWriter
func (m *Message) ToBytes() []byte {
	data, _ := json.MarshalIndent(m, "", "    ")
	return data
}

func (m *Message) FromBytes(b []byte) error {
	return json.Unmarshal(b, m)
}
