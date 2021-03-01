package basicauth

import (
	"log"
	"net/http"
)

type HTTPHandler struct {
	PasswordKeeper PasswordKeeper
	TokenKeeper    TokenKeeper
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Server is running and accepting connections"))
}

// Close signals mainHandler to disconnect from password keeper and token keeper
// and Call their Close() method accordingly.
func (h *HTTPHandler) Close() {
	if err := h.PasswordKeeper.Close(); err != nil {
		log.Printf("error closing passwords keeper: %v", err)
	} else {
		log.Println("closed password keeper")
	}
	if err := h.TokenKeeper.Close(); err != nil {
		log.Printf("error closing tokens keeper: %v", err)
	} else {
		log.Println("closed tokens keeper")
	}
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
