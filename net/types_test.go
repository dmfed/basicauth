package net

import (
	"log"
	"testing"
)

func TestMessageFromBytes(t *testing.T) {
	data := []byte(`{
		"AppToken": "",
		"Request": {
			"ID": "0000",
			"Action": "adduser",
			"Token": "",
			"UserName": "dmitry",
			"Password": "hello",
			"NewPassword": ""
		},
		"Response": {
			"ID": "",
			"OK": false,
			"Error": "",
			"Token": ""
		}
	}`)
	other := Message{Request: Request{ID: "0000", Action: "adduser", UserName: "dmitry", Password: "hello"},
		Response: Response{OK: false}}
	var m Message
	err := m.FromBytes(data)
	if err != nil {
		log.Println(err)
		t.Fail()
	}
	if m != other {
		t.Fail()
	}
}
