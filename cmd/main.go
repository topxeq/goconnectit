package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/topxeq/goconnectit"
)

func main() {
	// Parse command line arguments
	mode := flag.String("mode", "server", "Mode: server or client")
	addr := flag.String("addr", "0.0.0.0:8888", "Server listening address (for server mode)")
	serverAddr := flag.String("server", "127.0.0.1:8888", "Server address (for client mode)")
	localAddr := flag.String("local", "127.0.0.1:1080", "Local proxy address (for client mode)")
	password := flag.String("password", "12345678", "Encryption password")
	flag.Parse()

	// Validate mode
	if *mode != "server" && *mode != "client" {
		fmt.Printf("Invalid mode: %s. Mode must be 'server' or 'client'.\n", *mode)
		os.Exit(1)
	}

	// Validate password length
	if len(*password) < 8 {
		fmt.Println("Password must be at least 8 characters long.")
		os.Exit(1)
	}

	if *mode == "server" {
		// Start server
		s := goconnectit.NewServer(*addr, *password)
		fmt.Printf("Starting server on %s...\n", *addr)
		err := s.Start()
		if err != nil {
			fmt.Printf("Starting server failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Start client
		c := goconnectit.NewClient(*serverAddr, *localAddr, *password)
		fmt.Printf("Starting client with local proxy on %s...\n", *localAddr)
		err := c.Start()
		if err != nil {
			fmt.Printf("Starting client failed: %v\n", err)
			os.Exit(1)
		}
	}
}
