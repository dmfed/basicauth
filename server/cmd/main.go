package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/dmfed/basicauth/jsonstorage"
	"github.com/dmfed/basicauth/server"
	"github.com/dmfed/basicauth/tokens"
)

const tokenEnvVar = "BASIC_AUTH_TOKEN"

func main() {
	var (
		flagIPAddr        = flag.String("ip", "127.0.0.1", "ip address to listen on")
		flagPort          = flag.String("port", "8081", "port to listen on")
		flagPasswordsFile = flag.String("passwords", "", "password file to use")
		flagTokenDuration = flag.Duration("duration", time.Hour, "max duration while token is valid")
		flagCertFile      = flag.String("cert", "", "certificate file to use")
		flagKeyFile       = flag.String("key", "", "key file to use")
		flagMasterToken   = flag.String("token", "", "provide token via commandline")
	)
	flag.Parse()
	passkeeper, err := jsonstorage.NewJSONPasswordKeeper(*flagPasswordsFile)
	if err != nil {
		log.Printf("error opening passwors storage: %v", err)
		return
	}
	tokkeeper, err := tokens.NewMemSessionTokenKeeper(*flagTokenDuration)
	if err != nil {
		log.Printf("error opening token keeper: %v", err)
	}

	if *flagMasterToken == "" {
		if envtoken, ok := os.LookupEnv(tokenEnvVar); ok {
			*flagMasterToken = envtoken
		} else {
			log.Printf("%v variable not set and no token provided via CLI. running with no master key", tokenEnvVar)
		}
	}

	srv, err := server.New(*flagIPAddr, *flagPort, passkeeper, tokkeeper)
	if err != nil {
		log.Printf("error starting auth server: %v", err)
	}

	if *flagCertFile != "" && *flagKeyFile != "" {
		log.Fatal(srv.ListenAndServeTLS(*flagCertFile, *flagKeyFile))
	} else {
		log.Printf("warning: no certificate and/or key provided. TLS DISABLED!!!")
		log.Fatal(srv.ListenAndServe())
	}
}
