package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dmfed/basicauth"
	"github.com/dmfed/basicauth/jsonstorage"
)

func main() {
	var (
		flagFilename = flag.String("f", "", "storage file to use")
		flagNew      = flag.Bool("new", false, "create new storage and quit (requires filename)")
		flagAdd      = flag.Bool("add", false, "add user record (requires user password to be supplied)")
		flagDel      = flag.Bool("del", false, "delete user record")
		flagUpdate   = flag.Bool("upd", false, "update user password (requires user password to be supplied)")
		flagFind     = flag.Bool("find", false, "display user info in the storage")
		flagUsername = flag.String("u", "", "username to add/delete/update/find")
		flagPassword = flag.String("p", "", "password of user (if required)")
	)
	flag.Parse()

	if *flagFilename == "" {
		fmt.Println("filename not provided. exiting...")
		os.Exit(1)
	}

	if *flagNew {
		if _, err := jsonstorage.NewJSONPasswordKeeper(*flagFilename); err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		return
	}
	storage, err := jsonstorage.OpenJSONPasswordKeeper(*flagFilename)
	if err != nil {
		fmt.Printf("error opening password storage: %v", err)
		os.Exit(2)
	}
	fmt.Println("Opened storage:", *flagFilename)
	admin, err := basicauth.NewAdmin(storage)
	if err != nil {
		fmt.Printf("error getting admin interface to storage: %v", err)
		os.Exit(3)
	}

	if *flagFind && *flagUsername != "" {
		fmt.Printf("Lookup for user: %v\n", *flagUsername)
		userinfo, err := admin.AdminGetUserInfo(*flagUsername)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(userinfo)
		return
	}

	if *flagAdd && *flagUsername != "" && *flagPassword != "" {
		fmt.Printf("Adding user: %v\n", *flagUsername)
		if err := admin.AdminAddUser(*flagUsername, *flagPassword); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("Added user %v\n", *flagUsername)
		return
	}

	if *flagUpdate && *flagUsername != "" && *flagPassword != "" {
		if err := admin.AdminUpdateUserPassword(*flagUsername, *flagPassword); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("added user %v", *flagUsername)
	}

	if *flagDel && *flagUsername != "" {
		if err := admin.AdminDelUser(*flagUsername); err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		fmt.Printf("deleted user %v", *flagUsername)
		return
	}
	fmt.Println("not enough parameters provided. see %v --help", os.Args[0])
}
