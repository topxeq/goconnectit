# goconnectit

A Go-based encrypted SOCKS5 proxy service with server and client components.

## Features

- **Multiple Encryption Methods**: Supports DES, TXDEF, TXDEE, and TXDE encryption algorithms
- **SOCKS5 Proxy**: Full SOCKS5 protocol support (IPv4, IPv6, domain name)
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

### Quick Install (Recommended)

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/topxeq/goconnectit/master/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/topxeq/goconnectit/master/install.ps1 | iex
```

### Manual Install

Download the latest release from [GitHub Releases](https://github.com/topxeq/goconnectit/releases):

| Platform | File |
|----------|------|
| Linux x64 | goconnectit-linux-amd64.tar.gz |
| Linux ARM64 | goconnectit-linux-arm64.tar.gz |
| macOS Intel | goconnectit-darwin-amd64.tar.gz |
| macOS Apple Silicon | goconnectit-darwin-arm64.tar.gz |
| Windows x64 | goconnectit-windows-amd64.zip |

Extract and place the binary in your PATH.

### Build from Source

```bash
git clone https://github.com/topxeq/goconnectit.git
cd goconnectit
go build -o goconnectit cmd/main.go
```

## Usage

### Server Mode

Run on a remote server:

```bash
./goconnectit -mode server -addr 0.0.0.0:8888 -password yourpassword -encrypt txdee
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-addr`: Server listening address (default: 0.0.0.0:8888)
- `-password`: Encryption password (default: 12345678)
- `-encrypt`: Encryption method: des, txdef, txdee, or txde (default: des)
- `-debug` or `-v`: Enable verbose logging

### Client Mode

Run on your local machine:

```bash
./goconnectit -mode client -server your-server:8888 -local 127.0.0.1:1080 -password yourpassword -encrypt txdee
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-server`: Server address (default: 127.0.0.1:8888)
- `-local`: Local SOCKS5 proxy address (default: 127.0.0.1:1080)
- `-password`: Encryption password (default: 12345678)
- `-encrypt`: Encryption method: des, txdef, txdee, or txde (default: des)
- `-debug` or `-v`: Enable verbose logging

### Using the Proxy

Configure your application or browser to use SOCKS5 proxy at `127.0.0.1:1080`.

## As a Library

You can also use goconnectit as a library in your own Go projects:

```go
import "github.com/topxeq/goconnectit"

// Create a server with TXDEE encryption
server := goconnectit.NewServer("0.0.0.0:8888", "yourpassword", false, "txdee")
go server.Start()

// Create a client with TXDEE encryption
client := goconnectit.NewClient("your-server:8888", "127.0.0.1:1080", "yourpassword", false, "txdee")
go client.Start()
```

## Security

- DES: Uses DES encryption in CTR mode with a random IV for each connection
- TXDEF/TXDEE/TXDE: Custom stream ciphers with password-derived keys
- Make sure to use a strong password (at least 8 characters) and keep it secret
- Both server and client must use the same encryption method and password

## License

This project is licensed under the MIT License.
