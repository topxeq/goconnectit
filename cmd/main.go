package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/topxeq/goconnectit"
)

func main() {
	mode := flag.String("mode", "server", "Mode: server or client")
	addr := flag.String("addr", "0.0.0.0:8888", "Server listening address (for server mode)")
	serverAddr := flag.String("server", "127.0.0.1:8888", "Server address (for client mode)")
	localAddr := flag.String("local", "127.0.0.1:1080", "Local proxy address (for client mode)")
	password := flag.String("password", "12345678", "Encryption password")
	verbose := flag.Bool("debug", false, "Enable verbose mode")
	encrypt := flag.String("encrypt", "des", "Encryption method: des, txdef, txdee, or txde")
	flag.BoolVar(verbose, "v", false, "Enable verbose mode (shorthand)")
	flag.Parse()

	if *mode != "server" && *mode != "client" {
		fmt.Printf("Invalid mode: %s. Mode must be 'server' or 'client'.\n", *mode)
		os.Exit(1)
	}

	if len(*password) < 8 {
		fmt.Println("Password must be at least 8 characters long.")
		os.Exit(1)
	}

	if *encrypt != "des" && *encrypt != "txdef" && *encrypt != "txdee" && *encrypt != "txde" {
		fmt.Printf("Invalid encryption method: %s. Must be 'des', 'txdef', 'txdee', or 'txde'.\n", *encrypt)
		os.Exit(1)
	}

	if *mode == "server" {
		s := goconnectit.NewServer(*addr, *password, *verbose, *encrypt)
		fmt.Printf("Starting server on %s (encryption: %s)...\n", *addr, *encrypt)
		err := s.Start()
		if err != nil {
			fmt.Printf("Starting server failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		c := goconnectit.NewClient(*serverAddr, *localAddr, *password, *verbose, *encrypt)
		fmt.Printf("Starting client with local proxy on %s (encryption: %s)...\n", *localAddr, *encrypt)
		err := c.Start()
		if err != nil {
			fmt.Printf("Starting client failed: %v\n", err)
			os.Exit(1)
		}
	}
}
