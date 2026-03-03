// Package goconnectit provides an encrypted TCP proxy service with HTTP/HTTPS/SOCKS5 support.
package goconnectit

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version of the package
const Version = "1.0.0"

// Errors
var (
	ErrInvalidPassword     = errors.New("invalid password")
	ErrInvalidProtocol     = errors.New("invalid protocol")
	ErrConnectionClosed    = errors.New("connection closed")
	ErrHandshakeFailed     = errors.New("handshake failed")
	ErrSOCKS5Unsupported   = errors.New("unsupported SOCKS5 command")
	ErrInvalidConfig       = errors.New("invalid configuration")
)

// Logger interface for customizable logging
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// DefaultLogger implements Logger with timestamp prefix
type DefaultLogger struct {
	verbose bool
	prefix  string
}

// NewDefaultLogger creates a new DefaultLogger
func NewDefaultLogger(verbose bool, prefix string) *DefaultLogger {
	return &DefaultLogger{verbose: verbose, prefix: prefix}
}

func (l *DefaultLogger) log(level, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] [%s] %s %s\n", timestamp, level, l.prefix, msg)
}

// Debug logs debug messages (only when verbose is true)
func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	if l.verbose {
		l.log("DEBUG", format, args...)
	}
}

// Info logs info messages
func (l *DefaultLogger) Info(format string, args ...interface{}) {
	l.log("INFO", format, args...)
}

// Error logs error messages
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	l.log("ERROR", format, args...)
}

// ServerConfig holds server configuration
type ServerConfig struct {
	ListenAddr string // Address to listen on (e.g., ":8443")
	Password   string // Encryption password
	Verbose    bool   // Enable verbose logging
	Logger     Logger // Custom logger (optional)
}

// ClientConfig holds client configuration
type ClientConfig struct {
	LocalAddr  string // Local proxy address (e.g., ":8080")
	ServerAddr string // Remote server address
	Password   string // Encryption password
	Verbose    bool   // Enable verbose logging
	Logger     Logger // Custom logger (optional)
}

// ServerStatus represents server status
type ServerStatus struct {
	Running     bool
	ListenAddr  string
	Connections int
	StartTime   time.Time
}

// ClientStatus represents client status
type ClientStatus struct {
	Running     bool
	LocalAddr   string
	ServerAddr  string
	Connections int
	StartTime   time.Time
}

// Server represents the proxy server
type Server struct {
	config     ServerConfig
	listener   net.Listener
	connections map[net.Conn]struct{}
	connMutex  sync.RWMutex
	stopChan   chan struct{}
	wg         sync.WaitGroup
	logger     Logger
	startTime  time.Time
}

// Client represents the proxy client
type Client struct {
	config      ClientConfig
	listener    net.Listener
	connections map[net.Conn]struct{}
	connMutex   sync.RWMutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
	logger      Logger
	startTime   time.Time
}

// EncryptedConn wraps a net.Conn with encryption
type EncryptedConn struct {
	conn         net.Conn
	encryptor    cipher.Stream
	decryptor    cipher.Stream
	readBuffer   []byte
	writeBuffer  []byte
}

// deriveKey derives a 32-byte key from password using SHA-256
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// NewEncryptedConn creates a new encrypted connection
func NewEncryptedConn(conn net.Conn, password string, isServer bool) (*EncryptedConn, error) {
	key := deriveKey(password)

	// Generate random IV for encryption
	encryptIV := make([]byte, aes.BlockSize)
	if _, err := rand.Read(encryptIV); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Exchange IVs
	var decryptIV []byte
	if isServer {
		// Server receives client's IV first, then sends its own
		decryptIV = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(conn, decryptIV); err != nil {
			return nil, fmt.Errorf("failed to receive IV: %w", err)
		}
		if _, err := conn.Write(encryptIV); err != nil {
			return nil, fmt.Errorf("failed to send IV: %w", err)
		}
	} else {
		// Client sends IV first, then receives server's IV
		if _, err := conn.Write(encryptIV); err != nil {
			return nil, fmt.Errorf("failed to send IV: %w", err)
		}
		decryptIV = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(conn, decryptIV); err != nil {
			return nil, fmt.Errorf("failed to receive IV: %w", err)
		}
	}

	// Create ciphers
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	encryptor := cipher.NewCTR(block, encryptIV)
	decryptor := cipher.NewCTR(block, decryptIV)

	return &EncryptedConn{
		conn:        conn,
		encryptor:   encryptor,
		decryptor:   decryptor,
		readBuffer:  make([]byte, 4096),
		writeBuffer: make([]byte, 4096),
	}, nil
}

// Read reads and decrypts data from the connection
func (ec *EncryptedConn) Read(b []byte) (int, error) {
	n, err := ec.conn.Read(b)
	if err != nil {
		return n, err
	}
	ec.decryptor.XORKeyStream(b[:n], b[:n])
	return n, nil
}

// Write encrypts and writes data to the connection
func (ec *EncryptedConn) Write(b []byte) (int, error) {
	if len(ec.writeBuffer) < len(b) {
		ec.writeBuffer = make([]byte, len(b))
	}
	ec.encryptor.XORKeyStream(ec.writeBuffer[:len(b)], b)
	return ec.conn.Write(ec.writeBuffer[:len(b)])
}

// Close closes the underlying connection
func (ec *EncryptedConn) Close() error {
	return ec.conn.Close()
}

// LocalAddr returns the local address
func (ec *EncryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (ec *EncryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

// SetDeadline sets the deadline for the connection
func (ec *EncryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (ec *EncryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (ec *EncryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

// StartServer starts a new proxy server
func StartServer(config ServerConfig) (*Server, error) {
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("%w: listen address required", ErrInvalidConfig)
	}
	if config.Password == "" {
		return nil, fmt.Errorf("%w: password required", ErrInvalidConfig)
	}

	logger := config.Logger
	if logger == nil {
		logger = NewDefaultLogger(config.Verbose, "[SERVER]")
	}

	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", config.ListenAddr, err)
	}

	server := &Server{
		config:      config,
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
		stopChan:    make(chan struct{}),
		logger:      logger,
		startTime:   time.Now(),
	}

	server.wg.Add(1)
	go server.acceptLoop()

	logger.Info("Server started on %s", config.ListenAddr)
	return server, nil
}

// Stop stops the server
func (s *Server) Stop() error {
	close(s.stopChan)

	// Close listener
	if err := s.listener.Close(); err != nil {
		s.logger.Error("Failed to close listener: %v", err)
	}

	// Close all connections
	s.connMutex.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.connections = make(map[net.Conn]struct{})
	s.connMutex.Unlock()

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("Server stopped")
	return nil
}

// Status returns the current server status
func (s *Server) Status() ServerStatus {
	s.connMutex.RLock()
	connCount := len(s.connections)
	s.connMutex.RUnlock()

	return ServerStatus{
		Running:     true,
		ListenAddr:  s.config.ListenAddr,
		Connections: connCount,
		StartTime:   s.startTime,
	}
}

// Connections returns the number of active connections
func (s *Server) Connections() int {
	s.connMutex.RLock()
	defer s.connMutex.RUnlock()
	return len(s.connections)
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopChan:
					return
				default:
					s.logger.Error("Accept error: %v", err)
					continue
				}
			}

			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Track connection
	s.connMutex.Lock()
	s.connections[conn] = struct{}{}
	s.connMutex.Unlock()

	defer func() {
		s.connMutex.Lock()
		delete(s.connections, conn)
		s.connMutex.Unlock()
	}()

	s.logger.Debug("New connection from %s", conn.RemoteAddr())

	// Create encrypted connection
	encConn, err := NewEncryptedConn(conn, s.config.Password, true)
	if err != nil {
		s.logger.Error("Failed to create encrypted connection: %v", err)
		return
	}

	// Read handshake
	var handshake [1]byte
	if _, err := io.ReadFull(encConn, handshake[:]); err != nil {
		s.logger.Error("Failed to read handshake: %v", err)
		return
	}

	// Verify password (simple XOR check)
	expected := byte(len(s.config.Password) % 256)
	if handshake[0] != expected {
		s.logger.Error("Invalid password from %s", conn.RemoteAddr())
		return
	}

	// Read target address
	targetAddr, err := readTargetAddress(encConn)
	if err != nil {
		s.logger.Error("Failed to read target address: %v", err)
		return
	}

	s.logger.Debug("Connecting to target: %s", targetAddr)

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		s.logger.Error("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Send success response
	if _, err := encConn.Write([]byte{0x00}); err != nil {
		s.logger.Error("Failed to send response: %v", err)
		return
	}

	s.logger.Info("Proxying %s <-> %s", conn.RemoteAddr(), targetAddr)

	// Relay data
	s.relay(encConn, targetConn)
}

func (s *Server) relay(encConn *EncryptedConn, targetConn net.Conn) {
	done := make(chan struct{}, 2)

	s.logger.Debug("Server relay starting")

	// encConn -> targetConn
	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(targetConn, encConn)
		s.logger.Debug("encConn->targetConn copied %d bytes, err=%v", n, err)
		targetConn.Close()
	}()

	// targetConn -> encConn
	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(encConn, targetConn)
		s.logger.Debug("targetConn->encConn copied %d bytes, err=%v", n, err)
		encConn.Close()
	}()

	<-done
	s.logger.Debug("Server relay done")
}

// StartClient starts a new proxy client
func StartClient(config ClientConfig) (*Client, error) {
	if config.LocalAddr == "" {
		return nil, fmt.Errorf("%w: local address required", ErrInvalidConfig)
	}
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("%w: server address required", ErrInvalidConfig)
	}
	if config.Password == "" {
		return nil, fmt.Errorf("%w: password required", ErrInvalidConfig)
	}

	logger := config.Logger
	if logger == nil {
		logger = NewDefaultLogger(config.Verbose, "[CLIENT]")
	}

	listener, err := net.Listen("tcp", config.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", config.LocalAddr, err)
	}

	client := &Client{
		config:      config,
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
		stopChan:    make(chan struct{}),
		logger:      logger,
		startTime:   time.Now(),
	}

	client.wg.Add(1)
	go client.acceptLoop()

	logger.Info("Client started on %s, proxying to %s", config.LocalAddr, config.ServerAddr)
	return client, nil
}

// Stop stops the client
func (c *Client) Stop() error {
	close(c.stopChan)

	// Close listener
	if err := c.listener.Close(); err != nil {
		c.logger.Error("Failed to close listener: %v", err)
	}

	// Close all connections
	c.connMutex.Lock()
	for conn := range c.connections {
		conn.Close()
	}
	c.connections = make(map[net.Conn]struct{})
	c.connMutex.Unlock()

	// Wait for all goroutines to finish
	c.wg.Wait()

	c.logger.Info("Client stopped")
	return nil
}

// Status returns the current client status
func (c *Client) Status() ClientStatus {
	c.connMutex.RLock()
	connCount := len(c.connections)
	c.connMutex.RUnlock()

	return ClientStatus{
		Running:     true,
		LocalAddr:   c.config.LocalAddr,
		ServerAddr:  c.config.ServerAddr,
		Connections: connCount,
		StartTime:   c.startTime,
	}
}

// Connections returns the number of active connections
func (c *Client) Connections() int {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	return len(c.connections)
}

func (c *Client) acceptLoop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopChan:
			return
		default:
			conn, err := c.listener.Accept()
			if err != nil {
				select {
				case <-c.stopChan:
					return
				default:
					c.logger.Error("Accept error: %v", err)
					continue
				}
			}

			c.wg.Add(1)
			go c.handleConnection(conn)
		}
	}
}

func (c *Client) handleConnection(conn net.Conn) {
	defer c.wg.Done()
	defer conn.Close()

	// Track connection
	c.connMutex.Lock()
	c.connections[conn] = struct{}{}
	c.connMutex.Unlock()

	defer func() {
		c.connMutex.Lock()
		delete(c.connections, conn)
		c.connMutex.Unlock()
	}()

	c.logger.Debug("New connection from %s", conn.RemoteAddr())

	// Read first byte to detect protocol
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var firstByte [1]byte
	n, err := conn.Read(firstByte[:])
	if err != nil || n == 0 {
		c.logger.Error("Failed to read first byte: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	// Detect protocol
	if firstByte[0] == 0x05 {
		// SOCKS5
		c.handleSOCKS5(conn, firstByte[0])
	} else if firstByte[0] == 0x16 {
		// TLS handshake - client trying to connect directly with TLS
		// This happens when client uses HTTPS proxy URL instead of HTTP proxy URL
		c.logger.Error("Client sent TLS handshake. Use -x http://proxy:port for HTTPS URLs, not -x https://proxy:port")
		return
	} else if firstByte[0] == 'C' || firstByte[0] == 'G' || firstByte[0] == 'P' || firstByte[0] == 'D' || firstByte[0] == 'H' ||
		firstByte[0] == 'c' || firstByte[0] == 'g' || firstByte[0] == 'p' || firstByte[0] == 'd' || firstByte[0] == 'h' {
		// HTTP (CONNECT, GET, POST, DELETE, HEAD) - case insensitive
		c.handleHTTP(conn, firstByte[0])
	} else {
		c.logger.Error("Unknown protocol: %d (0x%02X). Expected SOCKS5(0x05) or HTTP method (C/G/P/D/H)", firstByte[0], firstByte[0])
	}
}

func (c *Client) handleHTTP(conn net.Conn, firstByte byte) {
	c.logger.Debug("Handling HTTP connection")

	// Read the rest of the first line
	reader := bufio.NewReader(conn)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		c.logger.Error("Failed to read HTTP request: %v", err)
		return
	}
	firstLine = string(firstByte) + firstLine

	// Parse the request
	parts := strings.Fields(firstLine)
	if len(parts) < 3 {
		c.logger.Error("Invalid HTTP request: %s", firstLine)
		return
	}
	method := parts[0]
	target := parts[1]

	var targetAddr string
	var isConnect bool

	if method == "CONNECT" {
		// HTTPS proxy
		isConnect = true
		targetAddr = target
		if !strings.Contains(targetAddr, ":") {
			targetAddr = targetAddr + ":443"
		}
		c.logger.Debug("HTTP CONNECT to %s", targetAddr)
	} else {
		// HTTP proxy
		isConnect = false
		parsedURL, err := url.Parse(target)
		if err != nil {
			c.logger.Error("Failed to parse URL %s: %v", target, err)
			return
		}
		targetAddr = parsedURL.Host
		if !strings.Contains(targetAddr, ":") {
			targetAddr = targetAddr + ":80"
		}
		c.logger.Debug("HTTP %s to %s", method, targetAddr)
	}

	// Connect to server and establish encrypted tunnel
	serverConn, err := net.DialTimeout("tcp", c.config.ServerAddr, 10*time.Second)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		return
	}
	defer serverConn.Close()

	encConn, err := NewEncryptedConn(serverConn, c.config.Password, false)
	if err != nil {
		c.logger.Error("Failed to create encrypted connection: %v", err)
		return
	}

	// Send handshake
	handshake := byte(len(c.config.Password) % 256)
	if _, err := encConn.Write([]byte{handshake}); err != nil {
		c.logger.Error("Failed to send handshake: %v", err)
		return
	}

	// Send target address
	if err := writeTargetAddress(encConn, targetAddr); err != nil {
		c.logger.Error("Failed to send target address: %v", err)
		return
	}

	// Read response
	var response [1]byte
	if _, err := io.ReadFull(encConn, response[:]); err != nil {
		c.logger.Error("Failed to read response: %v", err)
		return
	}
	if response[0] != 0x00 {
		c.logger.Error("Server returned error: %d", response[0])
		return
	}

	if isConnect {
		// Read and discard remaining headers for CONNECT requests
		// The browser may send headers after the CONNECT line, we need to consume them
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				c.logger.Error("Failed to read CONNECT headers: %v", err)
				return
			}
			c.logger.Debug("CONNECT header: %s", strings.TrimSpace(line))
			if line == "\r\n" || line == "\n" {
				break
			}
		}

		// Send 200 Connection Established
		responseStr := "HTTP/1.1 200 Connection Established\r\n\r\n"
		if _, err := conn.Write([]byte(responseStr)); err != nil {
			c.logger.Error("Failed to send response: %v", err)
			return
		}
		c.logger.Debug("Sent 200 Connection Established")
	} else {
		// For plain HTTP, forward the request through the tunnel
		// Read and forward remaining headers
		var headersBuilder strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				c.logger.Error("Failed to read headers: %v", err)
				return
			}
			headersBuilder.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		// Reconstruct request without full URL (just path)
		parsedURL, _ := url.Parse(target)
		newRequest := fmt.Sprintf("%s %s %s\r\n", method, parsedURL.Path, parts[2])
		newRequest += headersBuilder.String()
		c.logger.Debug("Forwarding request: %s", strings.ReplaceAll(newRequest, "\r\n", "\\r\\n"))
		if _, err := encConn.Write([]byte(newRequest)); err != nil {
			c.logger.Error("Failed to forward request: %v", err)
			return
		}
	}

	c.logger.Info("Proxying HTTP %s %s <-> %s", conn.RemoteAddr(), targetAddr, c.config.ServerAddr)

	// Relay data - need to use reader's buffered data for both CONNECT and plain HTTP
	// because bufio.Reader may have already buffered some data from conn
	buffered := reader.Buffered()
	c.logger.Debug("Buffered bytes before relay: %d", buffered)
	var bufferedData []byte
	if buffered > 0 {
		bufferedData = make([]byte, buffered)
		n, _ := reader.Read(bufferedData)
		c.logger.Debug("Read %d buffered bytes: %q", n, bufferedData[:n])
	}
	// Create a multi-reader that first returns buffered data, then reads from conn
	combinedReader := io.MultiReader(bytes.NewReader(bufferedData), conn)
	c.relayReader(combinedReader, conn, encConn)
}

func (c *Client) handleSOCKS5(conn net.Conn, firstByte byte) {
	c.logger.Debug("Handling SOCKS5 connection")

	// Read SOCKS5 greeting
	reader := bufio.NewReader(conn)
	// firstByte is 0x05, read the rest of greeting
	var nmethods byte
	if err := binary.Read(reader, binary.BigEndian, &nmethods); err != nil {
		c.logger.Error("Failed to read SOCKS5 greeting: %v", err)
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		c.logger.Error("Failed to read SOCKS5 methods: %v", err)
		return
	}

	// Check for no-auth method (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}

	// Send method selection
	if hasNoAuth {
		conn.Write([]byte{0x05, 0x00})
	} else {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	// Read SOCKS5 request
	var req [10]byte
	if _, err := io.ReadFull(reader, req[:3]); err != nil {
		c.logger.Error("Failed to read SOCKS5 request header: %v", err)
		return
	}
	if req[0] != 0x05 {
		c.logger.Error("Invalid SOCKS5 version: %d", req[0])
		return
	}
	if req[1] != 0x01 { // Only CONNECT command supported
		c.logger.Error("Unsupported SOCKS5 command: %d", req[1])
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var targetAddr string
	var atyp byte
	if err := binary.Read(reader, binary.BigEndian, &atyp); err != nil {
		c.logger.Error("Failed to read address type: %v", err)
		return
	}

	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			c.logger.Error("Failed to read IPv4: %v", err)
			return
		}
		var port uint16
		if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
			c.logger.Error("Failed to read port: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)

	case 0x03: // Domain name
		var len byte
		if err := binary.Read(reader, binary.BigEndian, &len); err != nil {
			c.logger.Error("Failed to read domain length: %v", err)
			return
		}
		domain := make([]byte, len)
		if _, err := io.ReadFull(reader, domain); err != nil {
			c.logger.Error("Failed to read domain: %v", err)
			return
		}
		var port uint16
		if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
			c.logger.Error("Failed to read port: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(domain), port)

	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			c.logger.Error("Failed to read IPv6: %v", err)
			return
		}
		var port uint16
		if err := binary.Read(reader, binary.BigEndian, &port); err != nil {
			c.logger.Error("Failed to read port: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("[%s]:%d", net.IP(ip[:]).String(), port)

	default:
		c.logger.Error("Unknown address type: %d", atyp)
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	c.logger.Debug("SOCKS5 CONNECT to %s", targetAddr)

	// Connect to server and establish encrypted tunnel
	serverConn, err := net.DialTimeout("tcp", c.config.ServerAddr, 10*time.Second)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}
	defer serverConn.Close()

	encConn, err := NewEncryptedConn(serverConn, c.config.Password, false)
	if err != nil {
		c.logger.Error("Failed to create encrypted connection: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send handshake
	handshake := byte(len(c.config.Password) % 256)
	if _, err := encConn.Write([]byte{handshake}); err != nil {
		c.logger.Error("Failed to send handshake: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send target address
	if err := writeTargetAddress(encConn, targetAddr); err != nil {
		c.logger.Error("Failed to send target address: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Read response
	var response [1]byte
	if _, err := io.ReadFull(encConn, response[:]); err != nil {
		c.logger.Error("Failed to read response: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if response[0] != 0x00 {
		c.logger.Error("Server returned error: %d", response[0])
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send success response
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	resp := []byte{0x05, 0x00, 0x00, 0x01}
	// Use 0.0.0.0 as the bind address (standard for SOCKS5 proxies)
	resp = append(resp, []byte{0, 0, 0, 0}...)
	resp = append(resp, byte(localAddr.Port>>8), byte(localAddr.Port))
	conn.Write(resp)

	c.logger.Info("Proxying SOCKS5 %s <-> %s", conn.RemoteAddr(), targetAddr)

	// Relay data - need to handle buffered data from bufio.Reader
	buffered := reader.Buffered()
	c.logger.Debug("SOCKS5 buffered bytes before relay: %d", buffered)
	var bufferedData []byte
	if buffered > 0 {
		bufferedData = make([]byte, buffered)
		n, _ := reader.Read(bufferedData)
		c.logger.Debug("SOCKS5 read %d buffered bytes", n)
	}
	combinedReader := io.MultiReader(bytes.NewReader(bufferedData), conn)
	c.relayReader(combinedReader, conn, encConn)
}

func (c *Client) relay(conn net.Conn, encConn *EncryptedConn) {
	done := make(chan struct{}, 2)

	// conn -> encConn
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(encConn, conn)
		encConn.Close()
	}()

	// encConn -> conn
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn, encConn)
		conn.Close()
	}()

	<-done
}

// relayReader is like relay but uses an io.Reader for the client side
// This is needed when we have buffered data from bufio.Reader
func (c *Client) relayReader(clientReader io.Reader, clientWriter io.Writer, encConn *EncryptedConn) {
	done := make(chan struct{}, 2)

	c.logger.Debug("relayReader starting")

	// clientReader -> encConn
	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(encConn, clientReader)
		c.logger.Debug("clientReader->encConn copied %d bytes, err=%v", n, err)
		encConn.Close()
	}()

	// encConn -> clientWriter
	go func() {
		defer func() { done <- struct{}{} }()
		n, err := io.Copy(clientWriter, encConn)
		c.logger.Debug("encConn->clientWriter copied %d bytes, err=%v", n, err)
		if closer, ok := clientWriter.(io.Closer); ok {
			closer.Close()
		}
	}()

	<-done
	c.logger.Debug("relayReader done")
}

// readTargetAddress reads a target address from the encrypted connection
func readTargetAddress(conn io.Reader) (string, error) {
	// Address format: [1 byte length][address bytes]
	var lenBuf [1]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return "", err
	}
	addr := make([]byte, lenBuf[0])
	if _, err := io.ReadFull(conn, addr); err != nil {
		return "", err
	}
	return string(addr), nil
}

// writeTargetAddress writes a target address to the encrypted connection
func writeTargetAddress(conn io.Writer, addr string) error {
	if len(addr) > 255 {
		return errors.New("address too long")
	}
	buf := make([]byte, 1+len(addr))
	buf[0] = byte(len(addr))
	copy(buf[1:], addr)
	_, err := conn.Write(buf)
	return err
}

// ParseAddr parses an address string into host and port
func ParseAddr(addr string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// EncryptData encrypts a byte slice using the password
func EncryptData(data []byte, password string) ([]byte, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Prepend IV to encrypted data
	result := make([]byte, aes.BlockSize+len(data))
	copy(result[:aes.BlockSize], iv)
	copy(result[aes.BlockSize:], encrypted)

	return result, nil
}

// DecryptData decrypts a byte slice using the password
func DecryptData(data []byte, password string) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("data too short")
	}

	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	encrypted := data[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	return decrypted, nil
}
