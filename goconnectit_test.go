package goconnectit

import (
	"crypto/cipher"
	"crypto/des"
	"io"
	"net"
	"testing"
	"time"
)

// TestNewServer tests creating a new server instance
func TestNewServer(t *testing.T) {
	addr := "0.0.0.0:8888"
	password := "12345678"
	verbose := false
	encryptMethod := "des"
	s := NewServer(addr, password, verbose, encryptMethod)
	if s.Addr != addr {
		t.Errorf("Expected server address to be %s, got %s", addr, s.Addr)
	}
	if s.Password != password {
		t.Errorf("Expected server password to be %s, got %s", password, s.Password)
	}
	if s.Verbose != verbose {
		t.Errorf("Expected server verbose to be %v, got %v", verbose, s.Verbose)
	}
	if s.EncryptMethod != encryptMethod {
		t.Errorf("Expected server encrypt method to be %s, got %s", encryptMethod, s.EncryptMethod)
	}
}

// TestNewClient tests creating a new client instance
func TestNewClient(t *testing.T) {
	serverAddr := "127.0.0.1:8888"
	localAddr := "127.0.0.1:1080"
	password := "12345678"
	verbose := false
	encryptMethod := "des"
	c := NewClient(serverAddr, localAddr, password, verbose, encryptMethod)
	if c.ServerAddr != serverAddr {
		t.Errorf("Expected server address to be %s, got %s", serverAddr, c.ServerAddr)
	}
	if c.LocalAddr != localAddr {
		t.Errorf("Expected local address to be %s, got %s", localAddr, c.LocalAddr)
	}
	if c.Password != password {
		t.Errorf("Expected client password to be %s, got %s", password, c.Password)
	}
	if c.Verbose != verbose {
		t.Errorf("Expected client verbose to be %v, got %v", verbose, c.Verbose)
	}
	if c.EncryptMethod != encryptMethod {
		t.Errorf("Expected client encrypt method to be %s, got %s", encryptMethod, c.EncryptMethod)
	}
}

// TestServerHandleConnectionWithValidData tests server handleConnection method with valid data
func TestServerHandleConnectionWithValidData(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "12345678", false, "des")
	
	// Test with normal data
	conn := &mockConn{data: []byte("test data")}
	s.handleConnection(conn)
}

// TestServerHandleConnectionWithReadError tests server handleConnection method with read error
func TestServerHandleConnectionWithReadError(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "12345678", false, "des")
	
	// Test with error in Read
	errConn := &mockConn{err: io.EOF}
	s.handleConnection(errConn)
}

// TestServerHandleConnectionWithWriteError tests server handleConnection method with write error
func TestServerHandleConnectionWithWriteError(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "12345678", false, "des")
	
	// Test with error in Write
	writeErrConn := &mockConn{data: []byte("test data"), err: io.EOF}
	s.handleConnection(writeErrConn)
}

// TestServerHandleConnectionWithInvalidPassword tests server handleConnection method with invalid password
func TestServerHandleConnectionWithInvalidPassword(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "short", false, "des") // Password is too short
	
	// Create a mock connection
	conn := &mockConn{data: []byte("test data")}
	
	// Handle the connection
	s.handleConnection(conn)
}

// TestEncryption tests the encryption and decryption functionality
func TestEncryption(t *testing.T) {
	password := "12345678"
	data := []byte("test data")

	// Create cipher
	block, err := des.NewCipher([]byte(password[:8]))
	if err != nil {
		t.Fatalf("Creating cipher failed: %v", err)
	}

	// Create encryption stream
	w := cipher.StreamWriter{S: cipher.NewCTR(block, []byte("00000000")), W: &mockWriter{}}
	_, err = w.Write(data)
	if err != nil {
		t.Fatalf("Encrypting data failed: %v", err)
	}

	// Create decryption stream
	r := cipher.StreamReader{S: cipher.NewCTR(block, []byte("00000000")), R: &mockReader{data: data}}
	buffer := make([]byte, len(data))
	n, err := r.Read(buffer)
	if err != nil && err != io.EOF {
		t.Fatalf("Decrypting data failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to read %d bytes, got %d", len(data), n)
	}
}

// TestServerHandleConnection tests server handleConnection method
func TestServerHandleConnection(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "12345678", false, "des")
	
	// Test with normal data
	conn := &mockConn{data: []byte("test data")}
	s.handleConnection(conn)
	
	// Test with error in Read
	errConn := &mockConn{err: io.EOF}
	s.handleConnection(errConn)
	
	// Test with error in Write
	writeErrConn := &mockConn{data: []byte("test data"), err: io.EOF}
	s.handleConnection(writeErrConn)
}

// TestServerStart tests server Start method
func TestServerStart(t *testing.T) {
	// Create a server with a random port
	s := NewServer("127.0.0.1:0", "12345678", false, "des")
	
	// Start the server in a goroutine
	errChan := make(chan error)
	go func() {
		errChan <- s.Start()
	}()
	
	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)
	
	// Send a test request to the server
	conn, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Errorf("Failed to connect to server: %v", err)
		return
	}
	defer conn.Close()
	
	// Send some data
	testData := []byte("test data")
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("Failed to write to server: %v", err)
		return
	}
	
	// Read the response
	buffer := make([]byte, len(testData))
	_, err = conn.Read(buffer)
	if err != nil && err != io.EOF {
		t.Errorf("Failed to read from server: %v", err)
		return
	}
	
	// Close the server
	// Note: We can't directly close the server, but the test will exit and the goroutine will be cleaned up
	t.Log("Server Start test completed")
}

// TestClientStart tests client Start method
func TestClientStart(t *testing.T) {
	// Create a client with a random local port
	c := NewClient("127.0.0.1:12345", "127.0.0.1:0", "12345678", false, "des")
	
	// Start the client in a goroutine
	errChan := make(chan error)
	go func() {
		errChan <- c.Start()
	}()
	
	// Give the client a moment to start
	time.Sleep(100 * time.Millisecond)
	
	// Try to connect to the client's local proxy
	conn, err := net.Dial("tcp", c.LocalAddr)
	if err != nil {
		t.Errorf("Failed to connect to client: %v", err)
		return
	}
	defer conn.Close()
	
	// Send some data
	testData := []byte("test data")
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("Failed to write to client: %v", err)
		return
	}
	
	// Note: We don't expect a response because the client can't connect to the server
	// But we can check that the client didn't crash
	t.Log("Client Start test completed")
}

// TestServerWithInvalidPassword tests server with invalid password
func TestServerWithInvalidPassword(t *testing.T) {
	s := NewServer("127.0.0.1:8888", "short", false, "des") // Password is too short
	
	// Create a mock connection
	conn := &mockConn{data: []byte("test data")}
	
	// Handle the connection
	s.handleConnection(conn)
	
	// Check if connection was closed
	t.Log("Server with invalid password test completed")
}

// TestTXDEFEncryption tests TXDEF encryption and decryption
func TestTXDEFEncryption(t *testing.T) {
	password := "12345678"
	data := []byte("test data")

	// Create TXDEF encrypt stream
	codeBytes := []byte(password)
	keyByte := codeBytes[len(codeBytes)-1]
	encryptStream := &txdefStream{
		code:    codeBytes,
		keyByte: keyByte,
		idx:     0,
	}

	// Encrypt data
	encrypted := make([]byte, len(data))
	encryptStream.XORKeyStream(encrypted, data)

	// Create TXDEF decrypt stream
	decryptStream := &txdefDecryptStream{
		code:    codeBytes,
		keyByte: keyByte,
		idx:     0,
	}

	// Decrypt data
	decrypted := make([]byte, len(encrypted))
	decryptStream.XORKeyStream(decrypted, encrypted)

	// Check if decrypted data matches original
	if string(decrypted) != string(data) {
		t.Errorf("TXDEF decrypted data doesn't match original: got %s, want %s", string(decrypted), string(data))
	}
}

// TestTXDEEEncryption tests TXDEE encryption and decryption
func TestTXDEEEncryption(t *testing.T) {
	password := "12345678"
	data := []byte("test data")

	// Create TXDEE encrypt stream
	codeBytes := []byte(password)
	keyByte := codeBytes[len(codeBytes)-1]
	encryptStream := &txdeeStream{
		code:    codeBytes,
		keyByte: keyByte,
		idx:     0,
	}

	// Encrypt data
	encrypted := make([]byte, len(data))
	encryptStream.XORKeyStream(encrypted, data)

	// Create TXDEE decrypt stream
	decryptStream := &txdeeDecryptStream{
		code:    codeBytes,
		keyByte: keyByte,
		idx:     0,
	}

	// Decrypt data
	decrypted := make([]byte, len(encrypted))
	decryptStream.XORKeyStream(decrypted, encrypted)

	// Check if decrypted data matches original
	if string(decrypted) != string(data) {
		t.Errorf("TXDEE decrypted data doesn't match original: got %s, want %s", string(decrypted), string(data))
	}
}

// TestTXDEEncryption tests TXDE encryption and decryption
func TestTXDEEncryption(t *testing.T) {
	password := "12345678"
	data := []byte("test data")

	// Create TXDE encrypt stream
	codeBytes := []byte(password)
	encryptStream := &txdeStream{
		code: codeBytes,
		idx:  0,
	}

	// Encrypt data
	encrypted := make([]byte, len(data))
	encryptStream.XORKeyStream(encrypted, data)

	// Create TXDE decrypt stream
	decryptStream := &txdeDecryptStream{
		code: codeBytes,
		idx:  0,
	}

	// Decrypt data
	decrypted := make([]byte, len(encrypted))
	decryptStream.XORKeyStream(decrypted, encrypted)

	// Check if decrypted data matches original
	if string(decrypted) != string(data) {
		t.Errorf("TXDE decrypted data doesn't match original: got %s, want %s", string(decrypted), string(data))
	}
}

// TestTXDEFEncryptedConn tests TXDEF encrypted connection with chunked protocol
func TestTXDEFEncryptedConn(t *testing.T) {
	password := "12345678"
	data := []byte("hello world test data")

	codeBytes := []byte(password)
	sumT := int(sumBytes(codeBytes))
	addLen := int((sumT % 5) + 2)
	encIndex := sumT % addLen

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientEnc := &txdefEncryptedConn{
		conn:     clientConn,
		code:     codeBytes,
		addLen:   addLen,
		encIndex: encIndex,
	}

	serverEnc := &txdefEncryptedConn{
		conn:     serverConn,
		code:     codeBytes,
		addLen:   addLen,
		encIndex: encIndex,
	}

	done := make(chan bool)
	go func() {
		buf := make([]byte, 1024)
		n, err := serverEnc.Read(buf)
		if err != nil {
			t.Errorf("Server read error: %v", err)
			return
		}
		if string(buf[:n]) != string(data) {
			t.Errorf("TXDEF chunked: got %s, want %s", string(buf[:n]), string(data))
		}
		done <- true
	}()

	_, err := clientEnc.Write(data)
	if err != nil {
		t.Fatalf("Client write error: %v", err)
	}

	<-done
}

// TestTXDEEEncryptedConn tests TXDEE encrypted connection with chunked protocol
func TestTXDEEEncryptedConn(t *testing.T) {
	password := "12345678"
	data := []byte("hello world test data")

	codeBytes := []byte(password)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientEnc := &txdeeEncryptedConn{
		conn: clientConn,
		code: codeBytes,
	}

	serverEnc := &txdeeEncryptedConn{
		conn: serverConn,
		code: codeBytes,
	}

	done := make(chan bool)
	go func() {
		buf := make([]byte, 1024)
		n, err := serverEnc.Read(buf)
		if err != nil {
			t.Errorf("Server read error: %v", err)
			return
		}
		if string(buf[:n]) != string(data) {
			t.Errorf("TXDEE chunked: got %s, want %s", string(buf[:n]), string(data))
		}
		done <- true
	}()

	_, err := clientEnc.Write(data)
	if err != nil {
		t.Fatalf("Client write error: %v", err)
	}

	<-done
}

// mockWriter is a mock implementation of io.Writer for testing

type mockWriter struct {
	data []byte
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	m.data = append(m.data, p...)
	return len(p), nil
}

// mockReader is a mock implementation of io.Reader for testing

type mockReader struct {
	data []byte
	pos  int
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

// mockConn is a mock implementation of net.Conn for testing

type mockConn struct {
	data []byte
	pos  int
	err  error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(b, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	m.data = append(m.data, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	return m.err
}

func (m *mockConn) LocalAddr() net.Addr {
	return &mockAddr{}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &mockAddr{}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return m.err
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return m.err
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return m.err
}

// mockAddr is a mock implementation of net.Addr for testing

type mockAddr struct{}

func (m *mockAddr) Network() string {
	return "tcp"
}

func (m *mockAddr) String() string {
	return "127.0.0.1:0"
}
