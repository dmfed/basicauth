package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dmfed/basicauth"
	"github.com/dmfed/basicauth/storage"
)

func main() {
	var (
		flagFilename = flag.String("f", "", "storage filename to use")
		flagNew      = flag.Bool("new", false, "create new storage and quit (requires filename)")
		flagAdd      = flag.Bool("adduser", false, "add user record")
		flagDel      = flag.Bool("deluser", false, "delete user record")
		flagUpdate   = flag.Bool("resetpwd", false, "reset user password")
		flagFind     = flag.Bool("show", false, "display user info in the storage")
		flagUsername = flag.String("u", "", "username to add/delete/update/find")
		flagPassword = flag.String("p", "", "password of user (if required)")
	)
	flag.Parse()

	if *flagFilename == "" {
		fmt.Println("filename not provided. exiting...")
		os.Exit(1)
	}

	if *flagNew {
		if _, err := storage.NewJSONPasswordKeeper(*flagFilename); err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		fmt.Printf("File storage created: %v", *flagFilename)
		return
	}

	storage, err := storage.OpenJSONPasswordKeeper(*flagFilename)
	if err != nil {
		fmt.Printf("error opening password storage: %v", err)
		os.Exit(2)
	}
	fmt.Println("Opened storage:", *flagFilename)

	admin, err := basicauth.NewAdminInterface(storage)
	if err != nil {
		fmt.Printf("error getting admin interface to storage: %v", err)
		os.Exit(3)
	}

	if *flagFind && *flagUsername != "" {
		fmt.Printf("Lookup for user: %v\n", *flagUsername)
		userinfo, err := admin.AdminGetAccount(*flagUsername)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(userinfo)
		return
	}

	if *flagAdd && *flagUsername != "" && *flagPassword != "" {
		fmt.Printf("Adding user: %v\n", *flagUsername)
		if err := admin.AdminAddAccount(*flagUsername); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("Added user %v\n", *flagUsername)
		return
	}

	if *flagUpdate && *flagUsername != "" && *flagPassword != "" {
		if err := admin.AdminResetUserPassword(*flagUsername); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("added user %v", *flagUsername)
	}

	if *flagDel && *flagUsername != "" {
		if err := admin.AdminDelAccount(*flagUsername); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("deleted user %v", *flagUsername)
		return
	}
	fmt.Printf("not enough parameters provided. see %v --help", os.Args[0])
}
