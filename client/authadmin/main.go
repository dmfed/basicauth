package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dmfed/basicauth/client"
)

const tokenEnvVar = "BASIC_AUTH_TOKEN"

func main() {
	var (
		flagIPAddr = flag.String("ip", "127.0.0.1", "ip address to listen on")
		flagPort   = flag.String("port", "8081", "port to listen on")
		/* flagUserName      = flag.String("user", "", "username to operate with")
		flagPassword      = flag.String("password", "", "password to operate with")
		flagOldPassword   = flag.String("oldpassword", "", "old password if required to execute command")
		flagAction        = flag.String("action", "", "action to perform") */
		flagRequireSecure = flag.Bool("secure", false, "require TLS connection")
		flagMasterToken   = flag.String("token", "", "provide token via commandline")
	)
	flag.Parse()
	if *flagMasterToken == "" {
		if envtoken, ok := os.LookupEnv(tokenEnvVar); ok {
			*flagMasterToken = envtoken
		} else {
			log.Printf("%v env variable not set and no token provided via CLI. running with no master key", tokenEnvVar)
		}
	}

	auth, err := client.New(*flagIPAddr, *flagPort, *flagMasterToken, *flagRequireSecure)
	if err != nil {
		log.Printf("could not start auth client: %v", err)
	}
	fmt.Println(auth.Close())
}
