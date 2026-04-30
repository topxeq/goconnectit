package goconnectit

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"
)

type Server struct {
	Addr          string
	Password      string
	Verbose       bool
	EncryptMethod string
}

type Client struct {
	ServerAddr    string
	LocalAddr     string
	Password      string
	Verbose       bool
	EncryptMethod string
}

func NewServer(addr, password string, verbose bool, encryptMethod string) *Server {
	return &Server{
		Addr:          addr,
		Password:      password,
		Verbose:       verbose,
		EncryptMethod: encryptMethod,
	}
}

func NewClient(serverAddr, localAddr, password string, verbose bool, encryptMethod string) *Client {
	return &Client{
		ServerAddr:    serverAddr,
		LocalAddr:     localAddr,
		Password:      password,
		Verbose:       verbose,
		EncryptMethod: encryptMethod,
	}
}

func log(verbose bool, format string, args ...interface{}) {
	if verbose {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("[%s] %s\n", timestamp, fmt.Sprintf(format, args...))
	}
}

func sumBytes(data []byte) byte {
	var b byte = 0
	for i := 0; i < len(data); i++ {
		b += data[i]
	}
	return b
}

func getRandomByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}

type txdefStream struct {
	code    []byte
	keyByte byte
	idx     int
}

func (s *txdefStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] + s.code[s.idx%len(s.code)] + byte(s.idx+1) + s.keyByte
		s.idx++
	}
}

type txdefDecryptStream struct {
	code    []byte
	keyByte byte
	idx     int
}

func (s *txdefDecryptStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] - s.code[s.idx%len(s.code)] - byte(s.idx+1) - s.keyByte
		s.idx++
	}
}

type txdeeStream struct {
	code    []byte
	keyByte byte
	idx     int
}

func (s *txdeeStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] + s.code[s.idx%len(s.code)] + byte(s.idx+1) + s.keyByte
		s.idx++
	}
}

type txdeeDecryptStream struct {
	code    []byte
	keyByte byte
	idx     int
}

func (s *txdeeDecryptStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] - s.code[s.idx%len(s.code)] - byte(s.idx+1) - s.keyByte
		s.idx++
	}
}

type txdeStream struct {
	code []byte
	idx  int
}

func (s *txdeStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] + s.code[s.idx%len(s.code)] + byte(s.idx+1)
		s.idx++
	}
}

type txdeDecryptStream struct {
	code []byte
	idx  int
}

func (s *txdeDecryptStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] - s.code[s.idx%len(s.code)] - byte(s.idx+1)
		s.idx++
	}
}

type encryptedConn struct {
	reader io.Reader
	writer io.Writer
	conn   net.Conn
}

func (ec *encryptedConn) Read(b []byte) (int, error) {
	return ec.reader.Read(b)
}

func (ec *encryptedConn) Write(b []byte) (int, error) {
	return ec.writer.Write(b)
}

func (ec *encryptedConn) Close() error {
	return ec.conn.Close()
}

func (ec *encryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

func (ec *encryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

func (ec *encryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

func (ec *encryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

func (ec *encryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

type txdefEncryptedConn struct {
	conn     net.Conn
	code     []byte
	addLen   int
	encIndex int
	readBuf  []byte
	readIdx  int
}

func (ec *txdefEncryptedConn) Read(b []byte) (int, error) {
	if ec.readBuf == nil || ec.readIdx >= len(ec.readBuf) {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(ec.conn, lenBuf)
		if err != nil {
			return 0, err
		}
		dataLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if dataLen < ec.addLen {
			return 0, fmt.Errorf("invalid TXDEF data length: %d", dataLen)
		}

		fullBuf := make([]byte, dataLen)
		_, err = io.ReadFull(ec.conn, fullBuf)
		if err != nil {
			return 0, err
		}

		keyByte := fullBuf[ec.encIndex]
		actualDataLen := dataLen - ec.addLen
		ec.readBuf = make([]byte, actualDataLen)

		for i := 0; i < actualDataLen; i++ {
			ec.readBuf[i] = fullBuf[ec.addLen+i] - ec.code[i%len(ec.code)] - byte(i+1) - keyByte
		}
		ec.readIdx = 0
	}

	n := copy(b, ec.readBuf[ec.readIdx:])
	ec.readIdx += n
	return n, nil
}

func (ec *txdefEncryptedConn) Write(b []byte) (int, error) {
	dataLen := len(b)

	randomBytes := make([]byte, ec.addLen)
	for i := 0; i < ec.addLen; i++ {
		randomBytes[i] = getRandomByte()
	}

	keyByte := randomBytes[ec.encIndex]

	totalLen := ec.addLen + dataLen
	buf := make([]byte, 2+totalLen)

	buf[0] = byte(totalLen >> 8)
	buf[1] = byte(totalLen)

	for i := 0; i < ec.addLen; i++ {
		buf[2+i] = randomBytes[i]
	}

	for i := 0; i < dataLen; i++ {
		buf[2+ec.addLen+i] = b[i] + ec.code[i%len(ec.code)] + byte(i+1) + keyByte
	}

	_, err := ec.conn.Write(buf)
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

func (ec *txdefEncryptedConn) Close() error {
	return ec.conn.Close()
}

func (ec *txdefEncryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

func (ec *txdefEncryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

func (ec *txdefEncryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

func (ec *txdefEncryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

func (ec *txdefEncryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

type txdeeEncryptedConn struct {
	conn    net.Conn
	code    []byte
	readBuf []byte
	readIdx int
}

func (ec *txdeeEncryptedConn) Read(b []byte) (int, error) {
	if ec.readBuf == nil || ec.readIdx >= len(ec.readBuf) {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(ec.conn, lenBuf)
		if err != nil {
			return 0, err
		}
		dataLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if dataLen < 4 {
			return 0, fmt.Errorf("invalid TXDEE data length: %d", dataLen)
		}

		fullBuf := make([]byte, dataLen)
		_, err = io.ReadFull(ec.conn, fullBuf)
		if err != nil {
			return 0, err
		}

		keyByte := fullBuf[1]
		actualDataLen := dataLen - 4
		ec.readBuf = make([]byte, actualDataLen)

		for i := 0; i < actualDataLen; i++ {
			ec.readBuf[i] = fullBuf[2+i] - ec.code[i%len(ec.code)] - byte(i+1) - keyByte
		}
		ec.readIdx = 0
	}

	n := copy(b, ec.readBuf[ec.readIdx:])
	ec.readIdx += n
	return n, nil
}

func (ec *txdeeEncryptedConn) Write(b []byte) (int, error) {
	dataLen := len(b)
	keyByte1 := getRandomByte()
	keyByte2 := getRandomByte()
	trailByte1 := getRandomByte()
	trailByte2 := getRandomByte()

	totalLen := 2 + dataLen + 2
	buf := make([]byte, 2+totalLen)

	buf[0] = byte(totalLen >> 8)
	buf[1] = byte(totalLen)

	buf[2] = keyByte1
	buf[3] = keyByte2

	for i := 0; i < dataLen; i++ {
		buf[4+i] = b[i] + ec.code[i%len(ec.code)] + byte(i+1) + keyByte2
	}

	buf[4+dataLen] = trailByte1
	buf[4+dataLen+1] = trailByte2

	_, err := ec.conn.Write(buf)
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}

func (ec *txdeeEncryptedConn) Close() error {
	return ec.conn.Close()
}

func (ec *txdeeEncryptedConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

func (ec *txdeeEncryptedConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

func (ec *txdeeEncryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

func (ec *txdeeEncryptedConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

func (ec *txdeeEncryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

func createDESStreams(password string, conn net.Conn) (*encryptedConn, error) {
	desKey := make([]byte, 8)
	copy(desKey, []byte(password))
	for i := len(password); i < 8; i++ {
		desKey[i] = 0
	}

	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}

	// Generate IV for write (encrypt) direction and send to peer
	ivWrite := make([]byte, des.BlockSize)
	_, err = rand.Read(ivWrite)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(ivWrite)
	if err != nil {
		return nil, err
	}

	// Read IV for read (decrypt) direction from peer
	ivRead := make([]byte, des.BlockSize)
	_, err = io.ReadFull(conn, ivRead)
	if err != nil {
		return nil, err
	}

	// Separate streams for read and write — each direction has its own keystream
	readStream := cipher.NewCTR(block, ivRead)
	writeStream := cipher.NewCTR(block, ivWrite)

	reader := &cipher.StreamReader{S: readStream, R: conn}
	writer := &cipher.StreamWriter{S: writeStream, W: conn}

	return &encryptedConn{reader: reader, writer: writer, conn: conn}, nil
}

func createTXDEFStreams(password string, conn net.Conn) (*txdefEncryptedConn, error) {
	codeT := password
	if codeT == "" {
		codeT = "topxeq"
	}
	codeBytes := []byte(codeT)

	sumT := int(sumBytes(codeBytes))
	addLen := int((sumT % 5) + 2)
	encIndex := sumT % addLen

	return &txdefEncryptedConn{
		conn:     conn,
		code:     codeBytes,
		addLen:   addLen,
		encIndex: encIndex,
	}, nil
}

func createTXDEEStreams(password string, conn net.Conn) (*txdeeEncryptedConn, error) {
	codeT := password
	if codeT == "" {
		codeT = "topxeq"
	}
	codeBytes := []byte(codeT)

	return &txdeeEncryptedConn{
		conn: conn,
		code: codeBytes,
	}, nil
}

func createTXDEStreams(password string, conn net.Conn) (*encryptedConn, error) {
	codeT := password
	if codeT == "" {
		codeT = "topxeq"
	}
	codeBytes := []byte(codeT)

	encryptStream := &txdeStream{
		code: codeBytes,
		idx:  0,
	}

	decryptStream := &txdeDecryptStream{
		code: codeBytes,
		idx:  0,
	}

	reader := &cipher.StreamReader{S: decryptStream, R: conn}
	writer := &cipher.StreamWriter{S: encryptStream, W: conn}

	return &encryptedConn{reader: reader, writer: writer, conn: conn}, nil
}

type netConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func createEncryptedStreams(encryptMethod, password string, conn net.Conn) (netConn, error) {
	switch encryptMethod {
	case "des":
		return createDESStreams(password, conn)
	case "txdef":
		return createTXDEFStreams(password, conn)
	case "txdee":
		return createTXDEEStreams(password, conn)
	case "txde":
		return createTXDEStreams(password, conn)
	default:
		return nil, fmt.Errorf("unsupported encryption method: %s", encryptMethod)
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	s.Addr = listener.Addr().String()
	log(s.Verbose, "Server started on %s", s.Addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log(s.Verbose, "Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	encryptedConn, err := createEncryptedStreams(s.EncryptMethod, s.Password, conn)
	if err != nil {
		log(s.Verbose, "Failed to create encrypted streams: %v", err)
		return
	}

	buf := make([]byte, 256)
	n, err := encryptedConn.Read(buf)
	if err != nil {
		log(s.Verbose, "Read error: %v", err)
		return
	}

	if n < 3 {
		log(s.Verbose, "Invalid SOCKS5 request")
		return
	}

	if buf[0] != 0x05 {
		log(s.Verbose, "Unsupported SOCKS version: %d", buf[0])
		return
	}

	nMethods := buf[1]
	if n < int(2+nMethods) {
		log(s.Verbose, "Invalid SOCKS5 method count")
		return
	}

	encryptedConn.Write([]byte{0x05, 0x00})

	n, err = encryptedConn.Read(buf)
	if err != nil {
		log(s.Verbose, "Read error: %v", err)
		return
	}

	if n < 4 {
		log(s.Verbose, "Invalid SOCKS5 request")
		return
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		log(s.Verbose, "Unsupported SOCKS5 command: %d", buf[1])
		return
	}

	var targetAddr string
	switch buf[3] {
	case 0x01:
		if n < 10 {
			log(s.Verbose, "Invalid IPv4 address")
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03:
		if n < 7 {
			log(s.Verbose, "Invalid domain name")
			return
		}
		domainLen := buf[4]
		if n < int(5+domainLen+2) {
			log(s.Verbose, "Invalid domain name length")
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[5+domainLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04:
		if n < 22 {
			log(s.Verbose, "Invalid IPv6 address")
			return
		}
		ip := net.IP(buf[4:20])
		port := uint16(buf[20])<<8 | uint16(buf[21])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		log(s.Verbose, "Unsupported address type: %d", buf[3])
		return
	}

	remoteConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log(s.Verbose, "Failed to connect to %s: %v", targetAddr, err)
		encryptedConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer remoteConn.Close()

	encryptedConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go io.Copy(remoteConn, encryptedConn)
	io.Copy(encryptedConn, remoteConn)
}

func (c *Client) Start() error {
	listener, err := net.Listen("tcp", c.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	c.LocalAddr = listener.Addr().String()
	log(c.Verbose, "Client started on %s", c.LocalAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log(c.Verbose, "Accept error: %v", err)
			continue
		}

		go c.handleConnection(conn)
	}
}

func (c *Client) handleConnection(conn net.Conn) {
	defer conn.Close()

	serverConn, err := net.Dial("tcp", c.ServerAddr)
	if err != nil {
		log(c.Verbose, "Failed to connect to server: %v", err)
		return
	}
	defer serverConn.Close()

	encryptedConn, err := createEncryptedStreams(c.EncryptMethod, c.Password, serverConn)
	if err != nil {
		log(c.Verbose, "Failed to create encrypted streams: %v", err)
		return
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		log(c.Verbose, "Read error: %v", err)
		return
	}

	_, err = encryptedConn.Write(buf[:n])
	if err != nil {
		log(c.Verbose, "Write error: %v", err)
		return
	}

	n, err = encryptedConn.Read(buf)
	if err != nil {
		log(c.Verbose, "Read error: %v", err)
		return
	}

	_, err = conn.Write(buf[:n])
	if err != nil {
		log(c.Verbose, "Write error: %v", err)
		return
	}

	n, err = conn.Read(buf)
	if err != nil {
		log(c.Verbose, "Read error: %v", err)
		return
	}

	_, err = encryptedConn.Write(buf[:n])
	if err != nil {
		log(c.Verbose, "Write error: %v", err)
		return
	}

	n, err = encryptedConn.Read(buf)
	if err != nil {
		log(c.Verbose, "Read error: %v", err)
		return
	}

	_, err = conn.Write(buf[:n])
	if err != nil {
		log(c.Verbose, "Write error: %v", err)
		return
	}

	go io.Copy(encryptedConn, conn)
	io.Copy(conn, encryptedConn)
}
