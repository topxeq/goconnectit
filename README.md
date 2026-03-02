# goconnectit

A Go-based proxy service that provides encrypted communication between server and client.

## Features

- **Encrypted Communication**: Uses DES encryption to secure data transmission between server and client
- **Multi-protocol Support**: Client provides http/https/socks5 proxy on a single port
- **Cross-platform**: Supports both Windows and Linux operating systems
- **Easy to use**: Simple command-line interface with configurable parameters
- **Modular design**: Can be used as a library in other Go projects
- **Single Executable**: Combined server and client in one binary

## Directory Structure

```
goconnectit/
├── cmd/
│   ├── main.go          # Combined server/client main program
│   ├── main_test.go     # Main program tests
├── goconnectit.go         # Core library functions
├── goconnectit_test.go    # Library tests
├── go.mod                 # Go module file
├── README.md              # This file
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
./goconnectit.exe -mode server -addr 0.0.0.0:8888 -password 12345678
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-addr`: Server listening address (default: 0.0.0.0:8888)
- `-password`: Encryption password (default: 12345678)

### Client Mode

```bash
./goconnectit.exe -mode client -server 127.0.0.1:8888 -local 127.0.0.1:1080 -password 12345678
```

- `-mode`: Operation mode (required, either "server" or "client")
- `-server`: Server address (default: 127.0.0.1:8888)
- `-local`: Local proxy address (default: 127.0.0.1:1080)
- `-password`: Encryption password (default: 12345678)

## As a Library

You can also use goconnectit as a library in your own Go projects:

```go
import "github.com/topxeq/goconnectit"

// Create a server
server := goconnectit.NewServer("0.0.0.0:8888", "12345678")
go server.Start()

// Create a client
client := goconnectit.NewClient("127.0.0.1:8888", "127.0.0.1:1080", "12345678")
go client.Start()
```

## Security

- The service uses DES encryption with CTR mode for data transmission
- The password is used to generate the encryption key
- Make sure to use a strong password and keep it secret

## License

This project is licensed under the MIT License.
