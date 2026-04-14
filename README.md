# goconnectit

A Go-based proxy service that provides encrypted communication between server and client.

## Features

- **Multiple Encryption Methods**: Supports DES, TXDEF, TXDEE, and TXDE encryption algorithms
- **Multi-protocol Support**: Client provides http/https/socks5 proxy on a single port
- **Cross-platform**: Supports both Windows and Linux operating systems
- **Easy to use**: Simple command-line interface with configurable parameters
- **Modular design**: Can be used as a library in other Go projects
- **Single Executable**: Combined server and client in one binary
- **Zero external dependencies**: All encryption algorithms are implemented inline

## Encryption Methods

| Method | Extra Bytes | Description |
|--------|-------------|-------------|
| `des` | 8 (IV) | DES encryption in CTR mode with random IV |
| `txdef` | 2~6 bytes | Custom encryption with variable random header |
| `txdee` | 4 bytes | Custom encryption with fixed 4-byte header/trailer |
| `txde` | 0 bytes | Lightweight stream encryption, no extra bytes |

### Algorithm Details

**TXDEF**:
- Adds 2~6 random bytes (based on password's SumBytes)
- Uses `randomBytes[encIndex]` as key byte
- Formula: `dst[i] = src[i] + code[idx%len] + byte(i+1) + keyByte`

**TXDEE**:
- Adds 4 bytes (2 random header + 2 random trailer)
- Uses second header byte as key byte
- Formula: `dst[i] = src[i] + code[idx%len] + byte(i+1) + keyByte`

**TXDE**:
- No extra bytes added
- Formula: `dst[i] = src[i] + code[idx%len] + byte(i+1)`
- Best for bandwidth-sensitive scenarios

## Directory Structure

```
goconnectit/
├── cmd/
│   └── main.go           # Combined server/client main program
├── goconnectit.go        # Core library functions
├── goconnectit_test.go   # Library tests
├── go.mod                # Go module file
└── README.md             # This file
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/topxeq/goconnectit.git
   cd goconnectit
   ```

2. Build the combined executable:
   ```bash
   # Build for Windows
   go build -o goconnectit.exe cmd/main.go

   # Build for Linux
   go build -o goconnectit cmd/main.go
   ```

## Usage

### Server Mode

```bash
./goconnectit.exe -mode server -addr 0.0.0.0:8888 -password 12345678 -encrypt txdee
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-addr`: Server listening address (default: 0.0.0.0:8888)
- `-password`: Encryption password (default: 12345678)
- `-encrypt`: Encryption method: des, txdef, txdee, or txde (default: des)
- `-debug` or `-v`: Enable verbose logging

### Client Mode

```bash
./goconnectit.exe -mode client -server 127.0.0.1:8888 -local 127.0.0.1:1080 -password 12345678 -encrypt txdee
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-server`: Server address (default: 127.0.0.1:8888)
- `-local`: Local proxy address (default: 127.0.0.1:1080)
- `-password`: Encryption password (default: 12345678)
- `-encrypt`: Encryption method: des, txdef, txdee, or txde (default: des)
- `-debug` or `-v`: Enable verbose logging

## As a Library

You can also use goconnectit as a library in your own Go projects:

```go
import "github.com/topxeq/goconnectit"

// Create a server with TXDEE encryption
server := goconnectit.NewServer("0.0.0.0:8888", "12345678", false, "txdee")
go server.Start()

// Create a client with TXDEE encryption
client := goconnectit.NewClient("127.0.0.1:8888", "127.0.0.1:1080", "12345678", false, "txdee")
go client.Start()
```

## Security

- DES: Uses DES encryption in CTR mode with a random IV for each connection
- TXDEF/TXDEE/TXDE: Custom stream ciphers with password-derived keys
- Make sure to use a strong password (at least 8 characters) and keep it secret
- Both server and client must use the same encryption method and password

## License

This project is licensed under the MIT License.
