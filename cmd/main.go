// Package main provides the command-line interface for goconnectit
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"goconnectit"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Parse command line flags
	mode := flag.String("mode", "", "Server or client mode (server/client)")
	listen := flag.String("listen", ":8080", "Address to listen on")
	server := flag.String("server", "", "Server address (client mode)")
	password := flag.String("password", "", "Encryption password")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	showVersion := flag.Bool("version", false, "Show version information")
	help := flag.Bool("help", false, "Show help information")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of goconnectit:\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "goconnectit -mode <server|client> -password <password> [options]\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nExamples:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  Server: goconnectit -mode server -listen :8443 -password secret\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  Client: goconnectit -mode client -listen :8080 -server :8443 -password secret\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("goconnectit version %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built: %s\n", date)
		fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	if *help {
		flag.Usage()
		return
	}

	// Validate required flags
	if *mode == "" {
		fmt.Fprintln(os.Stderr, "Error: -mode is required")
		flag.Usage()
		os.Exit(1)
	}

	if *password == "" {
		fmt.Fprintln(os.Stderr, "Error: -password is required")
		flag.Usage()
		os.Exit(1)
	}

	// Run based on mode
	switch strings.ToLower(*mode) {
	case "server":
		runServer(*listen, *password, *verbose)
	case "client":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "Error: -server is required in client mode")
			flag.Usage()
			os.Exit(1)
		}
		runClient(*listen, *server, *password, *verbose)
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid mode '%s', must be 'server' or 'client'\n", *mode)
		os.Exit(1)
	}
}

func runServer(listenAddr, password string, verbose bool) {
	server, err := goconnectit.StartServer(listenAddr, password, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Server started on %s\n", listenAddr)
	fmt.Println("Type 'help' for available commands")

	// Start REPL
	runREPL(server, nil)
}

func runClient(localAddr, serverAddr, password string, verbose bool) {
	client, err := goconnectit.StartClient(localAddr, serverAddr, password, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting client: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Client started on %s, proxying to %s\n", localAddr, serverAddr)
	fmt.Println("Type 'help' for available commands")

	// Start REPL
	runREPL(nil, client)
}

// Service interface for common operations
type Service interface {
	Stop() error
}

type statusProvider interface {
	Status() interface{}
	Connections() int
}

// Server wraps goconnectit.Server for status
type serverWrapper struct {
	*goconnectit.Server
}

func (s *serverWrapper) Status() interface{} {
	return s.Server.Status()
}

// Client wraps goconnectit.Client for status
type clientWrapper struct {
	*goconnectit.Client
}

func (c *clientWrapper) Status() interface{} {
	return c.Client.Status()
}

func runREPL(server *goconnectit.Server, client *goconnectit.Client) {
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel for commands
	cmdChan := make(chan string, 1)

	// Start goroutine to read input
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			cmdChan <- scanner.Text()
		}
	}()

	var service Service
	var statusProv statusProvider
	var startTime time.Time

	if server != nil {
		service = server
		statusProv = &serverWrapper{server}
		startTime = time.Now()
	} else if client != nil {
		service = client
		statusProv = &clientWrapper{client}
		startTime = time.Now()
	}

	for {
		select {
		case <-sigChan:
			fmt.Println("\nShutting down...")
			service.Stop()
			return

		case cmd := <-cmdChan:
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}

			switch strings.ToLower(cmd) {
			case "stop", "quit", "exit":
				fmt.Println("Stopping service...")
				service.Stop()
				return

			case "status":
				uptime := time.Since(startTime)
				connCount := statusProv.Connections()
				if server != nil {
					status := server.Status()
					fmt.Printf("Server Status:\n")
					fmt.Printf("  Listen Address: %s\n", status.ListenAddr)
					fmt.Printf("  Connections: %d\n", connCount)
					fmt.Printf("  Uptime: %s\n", uptime.Round(time.Second))
				} else if client != nil {
					status := client.Status()
					fmt.Printf("Client Status:\n")
					fmt.Printf("  Local Address: %s\n", status.LocalAddr)
					fmt.Printf("  Server Address: %s\n", status.ServerAddr)
					fmt.Printf("  Connections: %d\n", connCount)
					fmt.Printf("  Uptime: %s\n", uptime.Round(time.Second))
				}

			case "connections", "conn":
				connCount := statusProv.Connections()
				fmt.Printf("Active connections: %d\n", connCount)

			case "help", "?":
				printHelp()

			default:
				fmt.Printf("Unknown command: %s\n", cmd)
				fmt.Println("Type 'help' for available commands")
			}
		}
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  status       - Show service status")
	fmt.Println("  connections  - Show active connection count")
	fmt.Println("  stop         - Stop the service")
	fmt.Println("  help         - Show this help message")
	fmt.Println("  quit/exit    - Stop and exit")
}
