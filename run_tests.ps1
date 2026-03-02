# Run tests with coverage
Write-Host "Running tests..."
go test -run "TestNewServer|TestNewClient|TestEncryption" -cover
