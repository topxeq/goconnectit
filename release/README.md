# goconnectit

An encrypted TCP proxy service with HTTP/HTTPS/SOCKS5 support, written in Go.

## Features

- **Encrypted Tunnel**: AES-256-CTR stream encryption with password-based authentication
- **Multi-Protocol Support**: HTTP, HTTPS (CONNECT), and SOCKS5 proxy on a single port
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Easy to Use**: Simple command-line interface with REPL control
- **Library Ready**: Clean API for embedding in other applications

## Installation

### From Source

```bash
git clone https://github.com/yourusername/goconnectit.git
cd goconnectit
go build -o goconnectit ./cmd
```

### Pre-built Binaries

Download from the [Releases](https://github.com/yourusername/goconnectit/releases) page.

## Usage

### Server Mode

Start the server on a specified port:

```bash
goconnectit -mode server -listen :8443 -password yoursecret
```

### Client Mode

Start the client and connect to the server:

```bash
goconnectit -mode client -listen :8080 -server yourserver:8443 -password yoursecret
```

### Command Line Options

```
Usage: goconnectit [options]

Options:
  -mode string        "server" or "client" (required)
  -listen string      Address to listen on (default ":8080")
  -server string      Server address (client mode, required)
  -password string    Encryption password (required)
  -verbose            Enable verbose output
  -version            Show version information
  -help               Show help information
```

### Using as a Proxy

Once the client is running, you can use it as an HTTP/HTTPS/SOCKS5 proxy:

**HTTP/HTTPS Proxy:**
```bash
curl -x http://localhost:8080 http://httpbin.org/ip
curl -x http://localhost:8080 https://www.example.com
```

**SOCKS5 Proxy:**
```bash
curl --socks5 localhost:8080 http://httpbin.org/ip
```

**Environment Variables:**
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export ALL_PROXY=socks5://localhost:8080
```

### REPL Commands

While running, you can interact with the service through the REPL:

| Command | Description |
|---------|-------------|
| `status` | Show service status |
| `connections` | Show active connection count |
| `stop` | Stop the service |
| `help` | Show available commands |
| `quit` / `exit` | Stop and exit |

## Library Usage

You can use goconnectit as a library in your Go applications:

```go
package main

import (
    "goconnectit"
    "log"
)

func main() {
    // Start server
    server, err := goconnectit.StartServer(goconnectit.ServerConfig{
        ListenAddr: ":8443",
        Password:   "secret",
        Verbose:    true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer server.Stop()

    // Start client
    client, err := goconnectit.StartClient(goconnectit.ClientConfig{
        LocalAddr:  ":8080",
        ServerAddr: "localhost:8443",
        Password:   "secret",
        Verbose:    true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Stop()

    // Check status
    status := client.Status()
    log.Printf("Client running: %v", status.Running)
}
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Application│────▶│   Client    │────▶│   Server    │────▶ Target
│   (curl)    │     │ (Proxy Port)│     │ (Encrypted) │
└─────────────┘     └─────────────┘     └─────────────┘
                          │                    │
                    HTTP/HTTPS/SOCKS5    AES-256-CTR
```

### Encryption

- **Algorithm**: AES-256-CTR (Counter mode)
- **Key Derivation**: SHA-256 hash of password
- **IV Exchange**: Random IV exchanged at connection start
- **Stream Encryption**: No padding required, suitable for streaming

### Protocol Detection

The client automatically detects the protocol based on the first byte:
- `0x05`: SOCKS5
- `C`, `G`, `P`, `D`, `H`: HTTP (CONNECT, GET, POST, DELETE, HEAD)

## Testing

Run the test suite:

```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -cover ./...

# Run integration tests
go test -v -run Integration ./...
```

### Coverage

The project aims for >= 80% test coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Building

### Local Build

```bash
go build -o goconnectit ./cmd
```

### Cross-Platform Build

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o goconnectit-windows-amd64.exe ./cmd

# Linux
GOOS=linux GOARCH=amd64 go build -o goconnectit-linux-amd64 ./cmd

# macOS
GOOS=darwin GOARCH=amd64 go build -o goconnectit-darwin-amd64 ./cmd
GOOS=darwin GOARCH=arm64 go build -o goconnectit-darwin-arm64 ./cmd
```

## Configuration

### Server Configuration

| Field | Type | Description |
|-------|------|-------------|
| `ListenAddr` | string | Address to listen on (e.g., `:8443`) |
| `Password` | string | Encryption password |
| `Verbose` | bool | Enable debug logging |
| `Logger` | Logger | Custom logger interface |

### Client Configuration

| Field | Type | Description |
|-------|------|-------------|
| `LocalAddr` | string | Local proxy address (e.g., `:8080`) |
| `ServerAddr` | string | Remote server address |
| `Password` | string | Encryption password |
| `Verbose` | bool | Enable debug logging |
| `Logger` | Logger | Custom logger interface |

## Security Considerations

1. **Password Protection**: Choose a strong password to prevent brute-force attacks
2. **Network Security**: The encryption protects data in transit but doesn't provide authentication beyond the password
3. **Production Use**: Consider adding TLS layer for additional security in production environments

## License

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
