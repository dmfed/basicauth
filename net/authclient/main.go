package main

import (
	"flag"
	"log"
	"os"

	"github.com/dmfed/basicauth/net"
)

const tokenEnvVar = "BASICAUTH_TOKEN"

func main() {
	var (
		flagIPAddr = flag.String("ip", "127.0.0.1", "ip address to listen on")
		flagPort   = flag.String("port", "8081", "port to listen on")
		/* flagUserName      = flag.String("user", "", "username to operate with")
		flagPassword      = flag.String("password", "", "password to operate with")
		flagOldPassword   = flag.String("oldpassword", "", "old password if required to execute command")
		flagAction        = flag.String("action", "", "action to perform") */
		flagRequireSecure = flag.Bool("secure", false, "require TLS connection")
		flagAppToken      = flag.String("token", "", "provide token via commandline")
	)
	flag.Parse()
	if *flagAppToken == "" {
		if envtoken, ok := os.LookupEnv(tokenEnvVar); ok {
			*flagAppToken = envtoken
		} else {
			log.Printf("%v env variable not set and no token provided via CLI. running with no master key", tokenEnvVar)
		}
	}

	_, err := net.NewClient(*flagIPAddr, *flagPort, *flagAppToken, *flagRequireSecure)
	if err != nil {
		log.Printf("could not start auth client: %v", err)
	}
}
