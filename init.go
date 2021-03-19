package basicauth

var (
	globalHasher PasswordHasher
)

func init() {
	if globalHasher == nil {
		globalHasher = &defaultBcryptHasher{}
	}
}

// RegisterHasher allows to use any other package inmplementing
// password hashing and basicauth.PasswordHasher interface
// You can do it like this like this: include the following in your package code
// import "github.com/dmfed/basicauth"
//
// func init() {
//  //initialize your hasher (which need to implement basicauth.PasswordHasher)
// 	myhasher = New()
//  // This will run before init() in basicauth setting your hasher as default
//	basicauth.RegisterHasher(myhasher)
//}
//
// Then you can use your custom hashing package with basicauth like this:
//
//
// import (
//		_ "path/to/yourpackage" // this will seth basicauth's hasher
//		"github.com/dmfed/basicauth"
// )
// This way the init() in your custom package will override
// the default bcrypt implemented here.
// RegisterHasher can NOT be used once basicauth package is already inititalized.
// This is done to avoid possible confusion.
func RegisterHasher(h PasswordHasher) {
	if h != nil && globalHasher == nil {
		globalHasher = h
	}
}

func RegisterStorage(st UserAccountStorage) {

}
