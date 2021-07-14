package main

import (
	"os"
	"zRep/cmd/coordinator"
	"zRep/cmd/server"
	"zRep/cmd/client"
	// "zRep/test"
)

func main() {
	if len(os.Args) == 2 {
		switch role := os.Args[1]; role {
		case "0":
		case "coordinator":
			coordinator.Launch()
		case "1":
		case "server":
			server.Launch()
		case "2":
		case "client":
			client.Launch()
		default:
			coordinator.Launch()
		}
	}else {
		// test()
	}
}