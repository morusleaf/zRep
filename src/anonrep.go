package main

import (
	"os"
)

func main() {
	if len(os.Args) == 2 {
		switch role := os.Args[1]; role {
		case "0":
		case "coordinator":
			launchCoordinator()
		case "1":
		case "server":
			launchServer()
		case "2":
		case "client":
			launchClient()
		default:
			launchCoordinator()
		}
	}else {
		launchCoordinator()
	}
}