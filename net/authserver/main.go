package main

import (
	"flag"
	"log"
	"os"

	"github.com/dmfed/basicauth"
	"github.com/dmfed/basicauth/net"
)

const tokenEnvVar = "BASICAUTH_TOKEN"

func main() {
	var (
		flagIPAddr        = flag.String("ip", "127.0.0.1", "ip address to listen on")
		flagPort          = flag.String("port", "8081", "port to listen on")
		flagPasswordsFile = flag.String("passwords", "", "password file to use")
		// flagTokenDuration = flag.Duration("duration", time.Hour, "max duration while token is valid")
		flagCertFile = flag.String("cert", "", "certificate file to use")
		flagKeyFile  = flag.String("key", "", "key file to use")
		flagAppToken = flag.String("token", "", "provide token via commandline")
	)
	flag.Parse()
	storage, err := basicauth.OpenJSONPasswordKeeper(*flagPasswordsFile)
	if err != nil {
		log.Printf("error opening passwords storage: %v", err)
		return
	}

	logmgr, err := basicauth.NewLoginManager(storage)

	if *flagAppToken == "" {
		if envtoken, ok := os.LookupEnv(tokenEnvVar); ok {
			*flagAppToken = envtoken
		} else {
			log.Printf("%v variable not set and no token provided via CLI. running with no master key", tokenEnvVar)
		}
	}

	srv, err := net.NewLoginServer(*flagIPAddr, *flagPort, *flagAppToken, logmgr)
	if err != nil {
		log.Printf("error starting auth server: %v", err)
	}

	if *flagCertFile != "" && *flagKeyFile != "" {
		log.Fatal(srv.ListenAndServeTLS(*flagCertFile, *flagKeyFile))
	} else {
		log.Printf("WARNING: TLS IS DISABLED because no certificate and/or key provided. ")
		log.Fatal(srv.ListenAndServe())
	}
}
