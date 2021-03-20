package main

import (
	"flag"
	"log"
	"os"

	"github.com/dmfed/basicauth/net"
	"github.com/dmfed/basicauth/storage"
)

const (
	tokenAppsEnvVar  = "BASICAUTH_TOKEN"
	tokenAdminEnvVar = "BASICAUTH_ADMIN"
)

func main() {
	var (
		flagIPAddr        = flag.String("ip", "127.0.0.1", "ip address to listen on")
		flagPort          = flag.String("port", "8081", "port to listen on")
		flagPasswordsFile = flag.String("f", "", "password file to use")
		// flagTokenDuration = flag.Duration("duration", time.Hour, "max duration while token is valid")
		flagCertFile   = flag.String("cert", "", "TLS certificate file to use")
		flagKeyFile    = flag.String("key", "", "TLS key file to use")
		flagAdminToken = flag.String("admintoken", "", "provide admin token via command line")
		flagAppToken   = flag.String("token", "", "provide app token via command line")
	)
	flag.Parse()

	storage, err := storage.OpenJSONPasswordKeeper(*flagPasswordsFile)
	if err != nil {
		log.Printf("error opening passwords storage: %v", err)
		return
	}

	if *flagAppToken == "" {
		if envtoken, ok := os.LookupEnv(tokenAppsEnvVar); ok {
			*flagAppToken = envtoken
		} else {
			log.Printf("%v variable not set and no token provided via CLI. running with no app tokens", tokenAppsEnvVar)
		}
	}

	if *flagAdminToken == "" {
		if envtoken, ok := os.LookupEnv(tokenAdminEnvVar); ok {
			*flagAppToken = envtoken
		} else {
			log.Printf("%v variable not set and no token provided via CLI. running with no admin token", tokenAdminEnvVar)
		}
	}

	srv, err := net.NewLoginServer(storage, *flagIPAddr, *flagPort, *flagAdminToken, false, *flagAppToken)
	if err != nil {
		log.Printf("error initializing auth server: %v", err)
		return
	}

	if *flagCertFile != "" && *flagKeyFile != "" {
		log.Fatal(srv.ListenAndServeTLS(*flagCertFile, *flagKeyFile))
	} else {
		log.Println("WARNING: TLS IS DISABLED because no certificate and/or key provided.")
		log.Fatal(srv.ListenAndServe())
	}
}
