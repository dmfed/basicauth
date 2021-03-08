package net

import (
	"encoding/json"
)

// Request represents request to auth server
type Request struct {
	ID          string
	Action      string
	Token       string
	UserName    string
	Password    string
	NewPassword string
}

// Response represents response of auth server
type Response struct {
	ID    string
	OK    bool
	Error string
	Token string
}

// Message type is a basic transfer unit for Requests and Responses
type Message struct {
	AppToken string
	Request  Request
	Response Response
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
