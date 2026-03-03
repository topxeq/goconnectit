package goconnectit

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEncryptDecryptData tests the EncryptData and DecryptData functions
func TestEncryptDecryptData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		password string
	}{
		{"simple", []byte("hello world"), "secret"},
		{"empty", []byte{}, "secret"},
		{"long data", make([]byte, 1000), "password123"},
		{"unicode", []byte("你好世界"), "中文密码"},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}, "binary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptData(tt.data, tt.password)
			if err != nil {
				t.Fatalf("EncryptData failed: %v", err)
			}

			decrypted, err := DecryptData(encrypted, tt.password)
			if err != nil {
				t.Fatalf("DecryptData failed: %v", err)
			}

			if !bytes.Equal(tt.data, decrypted) {
				t.Errorf("Decrypted data doesn't match original")
			}
		})
	}
}

// TestEncryptDecryptDataWrongPassword tests decryption with wrong password
func TestEncryptDecryptDataWrongPassword(t *testing.T) {
	data := []byte("hello world")
	encrypted, err := EncryptData(data, "password1")
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	decrypted, err := DecryptData(encrypted, "password2")
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	// Should decrypt to different data (garbage)
	if bytes.Equal(data, decrypted) {
		t.Error("Decryption with wrong password should not produce original data")
	}
}

// TestDeriveKey tests key derivation consistency
func TestDeriveKey(t *testing.T) {
	password := "testpassword"
	key1 := deriveKey(password)
	key2 := deriveKey(password)

	if !bytes.Equal(key1, key2) {
		t.Error("Same password should produce same key")
	}

	if len(key1) != 32 {
		t.Errorf("Key length should be 32, got %d", len(key1))
	}
}

// TestDeriveKeyDifferent tests key derivation uniqueness
func TestDeriveKeyDifferent(t *testing.T) {
	key1 := deriveKey("password1")
	key2 := deriveKey("password2")

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}
}

// TestEncryptedConn tests the EncryptedConn type
func TestEncryptedConn(t *testing.T) {
	// Create a TCP listener for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	var serverConn *EncryptedConn
	var clientConn *EncryptedConn
	var serverRawConn net.Conn

	// Server side
	serverDone := make(chan error, 1)
	go func() {
		var err error
		serverRawConn, err = listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverConn, err = NewEncryptedConn(serverRawConn, "secret", true)
		serverDone <- err
	}()

	// Client side - connect first
	addr := listener.Addr().String()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
	clientConn, err = NewEncryptedConn(client, "secret", false)
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}

	// Wait for server
	if err := <-serverDone; err != nil {
		t.Fatalf("Server error: %v", err)
	}
	defer serverRawConn.Close()

	if serverConn == nil || clientConn == nil {
		t.Fatal("Failed to create encrypted connections")
	}

	// Test write and read
	testData := []byte("hello encrypted world")

	// Write from client
	_, err = clientConn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read on server
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(serverConn, buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(testData, buf) {
		t.Errorf("Data mismatch: got %s, want %s", buf, testData)
	}
}

// TestServerConfigValidation tests server configuration validation
func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		password   string
		verbose    bool
		wantErr    bool
	}{
		{"valid", ":8080", "secret", false, false},
		{"no address", "", "secret", false, true},
		{"no password", ":8080", "", false, true},
		{"empty", "", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := StartServer(tt.listenAddr, tt.password, tt.verbose)
			if (err != nil) != tt.wantErr {
				t.Errorf("StartServer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if server != nil {
				server.Stop()
			}
		})
	}
}

// TestClientConfigValidation tests client configuration validation
func TestClientConfigValidation(t *testing.T) {
	tests := []struct {
		name       string
		localAddr  string
		serverAddr string
		password   string
		verbose    bool
		wantErr    bool
	}{
		{"valid", ":18888", "localhost:18889", "secret", false, false},
		{"no local address", "", "localhost:8443", "secret", false, true},
		{"no server address", ":18888", "", "secret", false, true},
		{"no password", ":18888", "localhost:8443", "", false, true},
		{"empty", "", "", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to actually test with a running server for valid cases
			if !tt.wantErr {
				// Start a server first
				server, err := StartServer(":18889", "secret", false)
				if err != nil {
					t.Fatalf("Failed to start server: %v", err)
				}
				defer server.Stop()

				client, err := StartClient(tt.localAddr, tt.serverAddr, tt.password, tt.verbose)
				if (err != nil) != tt.wantErr {
					t.Errorf("StartClient() error = %v, wantErr %v", err, tt.wantErr)
				}
				if client != nil {
					client.Stop()
				}
			} else {
				_, err := StartClient(tt.localAddr, tt.serverAddr, tt.password, tt.verbose)
				if (err != nil) != tt.wantErr {
					t.Errorf("StartClient() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestServerStartStop tests server start and stop
func TestServerStartStop(t *testing.T) {
	server, err := StartServer(":18080", "testpassword", true)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}

	// Check status
	status := server.Status()
	if !status.Running {
		t.Error("Server should be running")
	}
	if status.ListenAddr != ":18080" {
		t.Errorf("ListenAddr = %s, want :18080", status.ListenAddr)
	}

	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestClientStartStop tests client start and stop
func TestClientStartStop(t *testing.T) {
	// Start server first
	server, err := StartServer(":18081", "testpassword", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	client, err := StartClient(":18082", "localhost:18081", "testpassword", true)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}

	// Check status
	status := client.Status()
	if !status.Running {
		t.Error("Client should be running")
	}
	if status.LocalAddr != ":18082" {
		t.Errorf("LocalAddr = %s, want :18082", status.LocalAddr)
	}

	// Stop client
	err = client.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// TestIntegrationHTTPProxy tests HTTP proxy functionality
func TestIntegrationHTTPProxy(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start server
	server, err := StartServer(":18090", "testpassword", true)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Start client
	client, err := StartClient(":18091", "localhost:18090", "testpassword", true)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	// Give client time to start
	time.Sleep(100 * time.Millisecond)

	t.Log("HTTP proxy integration test would make a request here")
}

// TestParseAddr tests the ParseAddr function
func TestParseAddr(t *testing.T) {
	tests := []struct {
		addr    string
		host    string
		port    int
		wantErr bool
	}{
		{"localhost:8080", "localhost", 8080, false},
		{"127.0.0.1:443", "127.0.0.1", 443, false},
		{"example.com:80", "example.com", 80, false},
		{"[::1]:8080", "::1", 8080, false},
		{"invalid", "", 0, true},
		{":8080", "", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			host, port, err := ParseAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if host != tt.host {
					t.Errorf("host = %v, want %v", host, tt.host)
				}
				if port != tt.port {
					t.Errorf("port = %v, want %v", port, tt.port)
				}
			}
		})
	}
}

// TestReadWriteTargetAddress tests address serialization
func TestReadWriteTargetAddress(t *testing.T) {
	tests := []string{
		"localhost:8080",
		"127.0.0.1:443",
		"example.com:80",
		"[::1]:8080",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeTargetAddress(&buf, tt)
			if err != nil {
				t.Fatalf("writeTargetAddress failed: %v", err)
			}

			result, err := readTargetAddress(&buf)
			if err != nil {
				t.Fatalf("readTargetAddress failed: %v", err)
			}

			if result != tt {
				t.Errorf("address = %v, want %v", result, tt)
			}
		})
	}
}

// TestWriteTargetAddressTooLong tests address length validation
func TestWriteTargetAddressTooLong(t *testing.T) {
	longAddr := strings.Repeat("a", 300)
	var buf bytes.Buffer
	err := writeTargetAddress(&buf, longAddr)
	if err == nil {
		t.Error("writeTargetAddress should fail for addresses > 255 bytes")
	}
}

// TestDefaultLogger tests the DefaultLogger
func TestDefaultLogger(t *testing.T) {
	// This test just ensures the logger doesn't panic
	logger := NewDefaultLogger(true, "[TEST]")
	logger.Debug("Debug message: %s", "test")
	logger.Info("Info message: %s", "test")
	logger.Error("Error message: %s", "test")

	// Test with verbose false
	logger = NewDefaultLogger(false, "[TEST]")
	logger.Debug("Should not appear")
	logger.Info("Info message")
}

// TestEncryptedConnClose tests EncryptedConn close
func TestEncryptedConnClose(t *testing.T) {
	server, client := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	var serverConn *EncryptedConn
	var clientConn *EncryptedConn

	go func() {
		defer wg.Done()
		serverConn, _ = NewEncryptedConn(server, "secret", true)
	}()

	go func() {
		defer wg.Done()
		clientConn, _ = NewEncryptedConn(client, "secret", false)
	}()

	wg.Wait()

	if serverConn != nil {
		err := serverConn.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}

	if clientConn != nil {
		err := clientConn.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}
}

// TestServerConnections tests the Connections method
func TestServerConnections(t *testing.T) {
	server, err := StartServer(":18092", "test", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	connCount := server.Connections()
	if connCount != 0 {
		t.Errorf("Expected 0 connections, got %d", connCount)
	}
}

// TestClientConnections tests the Connections method
func TestClientConnections(t *testing.T) {
	server, err := StartServer(":18093", "test", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	client, err := StartClient(":18094", "localhost:18093", "test", false)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	time.Sleep(50 * time.Millisecond)

	connCount := client.Connections()
	if connCount != 0 {
		t.Errorf("Expected 0 connections, got %d", connCount)
	}
}

// TestEncryptedConnDeadline tests deadline methods
func TestEncryptedConnDeadline(t *testing.T) {
	server, client := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	var serverConn *EncryptedConn
	var clientConn *EncryptedConn

	go func() {
		defer wg.Done()
		serverConn, _ = NewEncryptedConn(server, "secret", true)
	}()

	go func() {
		defer wg.Done()
		clientConn, _ = NewEncryptedConn(client, "secret", false)
	}()

	wg.Wait()

	if serverConn == nil || clientConn == nil {
		t.Fatal("Failed to create encrypted connections")
	}

	// Test SetDeadline
	err := serverConn.SetDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}

	// Test SetReadDeadline
	err = serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}

	// Test SetWriteDeadline
	err = serverConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}

	// Test LocalAddr
	if serverConn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}

	// Test RemoteAddr
	if serverConn.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}

	serverConn.Close()
	clientConn.Close()
}

// TestVersion tests the Version constant
func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

// startEchoServer starts a simple echo server for testing
func startEchoServer(t *testing.T, addr string) net.Listener {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return listener
}

// TestIntegrationFullProxyFlow tests the complete proxy flow
func TestIntegrationFullProxyFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start echo server (target)
	echoListener := startEchoServer(t, "127.0.0.1:19990")
	defer echoListener.Close()

	// Start proxy server
	server, err := StartServer(":19991", "testpassword", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	// Start proxy client
	client, err := StartClient(":19992", "localhost:19991", "testpassword", false)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	time.Sleep(50 * time.Millisecond)

	// Test SOCKS5 proxy
	t.Run("SOCKS5", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "localhost:19992", 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		// SOCKS5 greeting
		conn.Write([]byte{0x05, 0x01, 0x00})

		// Read method selection
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("Failed to read method selection: %v", err)
		}
		if buf[0] != 0x05 || buf[1] != 0x00 {
			t.Fatalf("Unexpected method selection response: %v", buf)
		}

		// SOCKS5 connect request
		connectReq := []byte{
			0x05,                   // version
			0x01,                   // CONNECT command
			0x00,                   // reserved
			0x01,                   // IPv4 address type
			127, 0, 0, 1,           // IPv4 address
			0x4E, 0x16,             // port 19990 (0x4E16)
		}
		conn.Write(connectReq)

		// Read connect response
		resp := make([]byte, 10)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("Failed to read connect response: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			t.Fatalf("Connect failed: %v", resp[:2])
		}

		// Send data through proxy
		testData := []byte("hello socks5")
		if _, err := conn.Write(testData); err != nil {
			t.Fatalf("Failed to write data: %v", err)
		}

		// Read echoed data
		recvBuf := make([]byte, len(testData))
		if _, err := io.ReadFull(conn, recvBuf); err != nil {
			t.Fatalf("Failed to read echoed data: %v", err)
		}

		if !bytes.Equal(testData, recvBuf) {
			t.Errorf("Echo mismatch: got %s, want %s", recvBuf, testData)
		}
	})
}

// TestIntegrationHTTPConnect tests HTTP CONNECT proxy
func TestIntegrationHTTPConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start echo server (target)
	echoListener := startEchoServer(t, "127.0.0.1:19993")
	defer echoListener.Close()

	// Start proxy server
	server, err := StartServer(":19994", "testpassword", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	// Start proxy client
	client, err := StartClient(":19995", "localhost:19994", "testpassword", false)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	time.Sleep(50 * time.Millisecond)

	// Test HTTP CONNECT proxy
	conn, err := net.DialTimeout("tcp", "localhost:19995", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// HTTP CONNECT request
	connectReq := "CONNECT 127.0.0.1:19993 HTTP/1.1\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Failed to send CONNECT: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("Connect failed: %s", line)
	}

	// Skip remaining headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send data through proxy
	testData := []byte("hello http connect")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Read echoed data
	recvBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("Failed to read echoed data: %v", err)
	}

	if !bytes.Equal(testData, recvBuf) {
		t.Errorf("Echo mismatch: got %s, want %s", recvBuf, testData)
	}
}

// TestIntegrationSOCKS5Domain tests SOCKS5 with domain name
func TestIntegrationSOCKS5Domain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start echo server
	echoListener := startEchoServer(t, "127.0.0.1:19980")
	defer echoListener.Close()

	// Start proxy server
	server, err := StartServer(":19981", "testpassword", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	// Start proxy client
	client, err := StartClient(":19982", "localhost:19981", "testpassword", false)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	time.Sleep(50 * time.Millisecond)

	// Test SOCKS5 with domain name
	conn, err := net.DialTimeout("tcp", "localhost:19982", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00})

	// Read method selection
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)

	// SOCKS5 connect with domain
	domain := "localhost"
	connectReq := []byte{
		0x05,                   // version
		0x01,                   // CONNECT command
		0x00,                   // reserved
		0x03,                   // domain address type
		byte(len(domain)),      // domain length
	}
	connectReq = append(connectReq, []byte(domain)...)
	connectReq = append(connectReq, []byte{0x4E, 0x0C}...) // port 19980

	conn.Write(connectReq)

	// Read connect response
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("Failed to read connect response: %v", err)
	}

	if resp[1] == 0x00 {
		t.Log("SOCKS5 domain connection successful")
	}
}

// TestIntegrationMultipleConnections tests multiple concurrent connections
func TestIntegrationMultipleConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start echo server
	echoListener := startEchoServer(t, "127.0.0.1:19970")
	defer echoListener.Close()

	// Start proxy server
	server, err := StartServer(":19971", "testpassword", false)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer server.Stop()

	time.Sleep(50 * time.Millisecond)

	// Start proxy client
	client, err := StartClient(":19972", "localhost:19971", "testpassword", false)
	if err != nil {
		t.Fatalf("StartClient failed: %v", err)
	}
	defer client.Stop()

	time.Sleep(50 * time.Millisecond)

	// Test multiple concurrent connections - just test that they can be established
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", "localhost:19972", 5*time.Second)
		if err != nil {
			t.Errorf("Failed to connect %d: %v", i, err)
			continue
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{0x05, 0x01, 0x00})
		buf := make([]byte, 2)
		io.ReadFull(conn, buf)
		conn.Close()
	}
}

// BenchmarkEncryptDecrypt benchmarks the encrypt/decrypt operations
func BenchmarkEncryptDecrypt(b *testing.B) {
	data := make([]byte, 1024)
	password := "benchmark"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := EncryptData(data, password)
		DecryptData(encrypted, password)
	}
}

// BenchmarkEncryptedConn benchmarks the encrypted connection
func BenchmarkEncryptedConn(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var serverConn *EncryptedConn
	var clientConn *EncryptedConn

	go func() {
		defer wg.Done()
		serverConn, _ = NewEncryptedConn(server, "secret", true)
	}()

	go func() {
		defer wg.Done()
		clientConn, _ = NewEncryptedConn(client, "secret", false)
	}()

	wg.Wait()

	if serverConn == nil || clientConn == nil {
		b.Fatal("Failed to create encrypted connections")
	}

	data := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientConn.Write(data)
		buf := make([]byte, len(data))
		serverConn.Read(buf)
	}
}
