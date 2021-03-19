package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dmfed/basicauth/net"
)

const tokenEnvVar = "BASICAUTH_TOKEN"

func main() {
	var (
		flagIPAddr         = flag.String("ip", "127.0.0.1", "ip address to connect to")
		flagPort           = flag.String("port", "8081", "port to listen on")
		flagRequireSecure  = flag.Bool("secure", false, "require TLS connection")
		flagAppToken       = flag.String("token", "", "provide token via commandline")
		flagGetCommand     = flag.Bool("get", false, "get info for specified user")
		flagAddUserCommand = flag.Bool("add", false, "add user")
		flagDelUserCommand = flag.Bool("del", false, "delete user")
		flagResetUserPass  = flag.Bool("reset", false, "reset password for specified user")
		flagUserName       = flag.String("u", "", "username")
	)
	flag.Parse()
	if *flagAppToken == "" {
		if envtoken, ok := os.LookupEnv(tokenEnvVar); ok {
			*flagAppToken = envtoken
		} else {
			log.Printf("%v env variable not set and no token provided via CLI. running with no master key", tokenEnvVar)
		}
	}

	client, err := net.NewRemoteAdminInterface(*flagIPAddr, *flagPort, *flagAppToken, *flagRequireSecure)
	if err != nil {
		log.Printf("could not start auth client: %v", err)
	}
	if *flagGetCommand {
		fmt.Println(client.AdminGetAccount(*flagUserName))
	} else if *flagAddUserCommand {
		fmt.Println(client.AdminAddAccount(*flagUserName))
	} else if *flagResetUserPass {
		fmt.Println(client.AdminResetUserPassword(*flagUserName))
	} else if *flagDelUserCommand {
		fmt.Println(client.AdminDelAccount(*flagUserName))
	}
}
