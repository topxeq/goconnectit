package goconnectit

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"io"
	"net"
)

// Server struct contains server configuration information
type Server struct {
	Addr     string // Server listening address
	Password string // Encryption password
}

// Client struct contains client configuration information
type Client struct {
	ServerAddr string // Server address
	LocalAddr  string // Local listening address
	Password   string // Encryption password
}

// NewServer creates a new server instance
func NewServer(addr, password string) *Server {
	return &Server{
		Addr:     addr,
		Password: password,
	}
}

// NewClient creates a new client instance
func NewClient(serverAddr, localAddr, password string) *Client {
	return &Client{
		ServerAddr: serverAddr,
		LocalAddr:  localAddr,
		Password:   password,
	}
}

// Start starts the server, begins listening and handling connections
func (s *Server) Start() error {
	// Listen for TCP connections
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listening failed: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Server started successfully, listening on: %s\n", s.Addr)

	// Infinite loop to handle new connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accepting connection failed: %v\n", err)
			continue
		}

		// Create a goroutine for each connection
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Create encryption/decryption cipher
	block, err := des.NewCipher([]byte(s.Password[:8])) // Use first 8 bytes of password as DES key
	if err != nil {
		fmt.Printf("creating cipher failed: %v\n", err)
		return
	}

	// Create encryption and decryption streams
	r := cipher.StreamReader{S: cipher.NewCTR(block, []byte("00000000")), R: conn}
	w := cipher.StreamWriter{S: cipher.NewCTR(block, []byte("00000000")), W: conn}

	// Read data from client
	buffer := make([]byte, 4096)
	for {
		n, err := r.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("reading data failed: %v\n", err)
			}
			break
		}

		// Process data (simply echo back to client here)
		_, err = w.Write(buffer[:n])
		if err != nil {
			fmt.Printf("writing data failed: %v\n", err)
			break
		}
	}
}

// Start starts the client, begins listening for local proxy requests
func (c *Client) Start() error {
	// Listen for local proxy requests
	listener, err := net.Listen("tcp", c.LocalAddr)
	if err != nil {
		return fmt.Errorf("local listening failed: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Client started successfully, local proxy address: %s\n", c.LocalAddr)

	// Infinite loop to handle new proxy requests
	for {
		localConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accepting local connection failed: %v\n", err)
			continue
		}

		// Handle proxy request
		go c.handleProxyRequest(localConn)
	}
}

// handleProxyRequest handles a proxy request
func (c *Client) handleProxyRequest(localConn net.Conn) {
	defer localConn.Close()

	// Connect to server
	serverConn, err := net.Dial("tcp", c.ServerAddr)
	if err != nil {
		fmt.Printf("connecting to server failed: %v\n", err)
		return
	}
	defer serverConn.Close()

	// Create encryption/decryption cipher
	block, err := des.NewCipher([]byte(c.Password[:8])) // Use first 8 bytes of password as DES key
	if err != nil {
		fmt.Printf("creating cipher failed: %v\n", err)
		return
	}

	// Create encryption and decryption streams
	serverReader := cipher.StreamReader{S: cipher.NewCTR(block, []byte("00000000")), R: serverConn}
	serverWriter := cipher.StreamWriter{S: cipher.NewCTR(block, []byte("00000000")), W: serverConn}

	// Read data from local client and forward to server
	go func() {
		// Read data from local client
		buffer := make([]byte, 4096)
		for {
			n, err := localConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("reading local data failed: %v\n", err)
				}
				break
			}

			// Encrypt and send to server
			_, err = serverWriter.Write(buffer[:n])
			if err != nil {
				fmt.Printf("sending data to server failed: %v\n", err)
				break
			}
		}
	}()

	// Read data from server and forward to local client
	go func() {
		// Read data from server
		buffer := make([]byte, 4096)
		for {
			n, err := serverReader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("reading server data failed: %v\n", err)
				}
				break
			}

			// Send to local client
			_, err = localConn.Write(buffer[:n])
			if err != nil {
				fmt.Printf("sending data to local client failed: %v\n", err)
				break
			}
		}
	}()
}
