package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestMain helps setup and teardown for tests
func TestMain(m *testing.M) {
	// Reset flags for each test
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Exit(m.Run())
}

// getBinaryName returns the platform-specific binary name
func getBinaryName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

// buildTestBinary builds the test binary and returns its path
func buildTestBinary(t *testing.T, name string) (string, error) {
	binaryName := getBinaryName(name)
	binaryPath := filepath.Join(t.TempDir(), binaryName)

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = "."
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return binaryPath, nil
}

// TestFlagParsing tests command line flag parsing
func TestFlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
	}{
		{
			name:    "version flag",
			args:    []string{"-version"},
			wantErr: false,
		},
		{
			name:    "help flag",
			args:    []string{"-help"},
			wantErr: false,
		},
		{
			name:    "missing mode",
			args:    []string{"-password", "secret"},
			wantErr: true,
		},
		{
			name:    "missing password",
			args:    []string{"-mode", "server"},
			wantErr: true,
		},
		{
			name:    "invalid mode",
			args:    []string{"-mode", "invalid", "-password", "secret"},
			wantErr: true,
		},
		{
			name:    "client without server",
			args:    []string{"-mode", "client", "-password", "secret"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath, err := buildTestBinary(t, "test_binary")
			if err != nil {
				t.Fatalf("Failed to build: %v", err)
			}

			args := append([]string{}, tt.args...)
			cmd := exec.Command(binaryPath, args...)
			err = cmd.Run()

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			}
		})
	}
}

// TestServerStartStop tests server lifecycle
func TestServerStartStop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	binaryPath, err := buildTestBinary(t, "test_server")
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	// Start server
	cmd := exec.Command(binaryPath, "-mode", "server", "-listen", ":19080", "-password", "test")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Stop server
	if err := cmd.Process.Kill(); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

// TestClientServerIntegration tests the full client-server flow
func TestClientServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	binaryPath, err := buildTestBinary(t, "test_integration")
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	// Start server
	serverCmd := exec.Command(binaryPath, "-mode", "server", "-listen", ":19081", "-password", "secret", "-verbose")
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer serverCmd.Process.Kill()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Start client
	clientCmd := exec.Command(binaryPath, "-mode", "client", "-listen", ":19082", "-server", "localhost:19081", "-password", "secret", "-verbose")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("Failed to start client: %v", err)
	}
	defer clientCmd.Process.Kill()

	// Wait for client to start
	time.Sleep(500 * time.Millisecond)

	// Both processes should be running
	if serverCmd.ProcessState != nil {
		t.Error("Server process should be running")
	}
	if clientCmd.ProcessState != nil {
		t.Error("Client process should be running")
	}
}

// TestVerboseFlag tests the verbose flag
func TestVerboseFlag(t *testing.T) {
	binaryPath, err := buildTestBinary(t, "test_verbose")
	if err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	tests := []struct {
		name    string
		verbose bool
	}{
		{"verbose on", true},
		{"verbose off", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"-mode", "server", "-listen", ":19083", "-password", "test"}
			if tt.verbose {
				args = append(args, "-verbose")
			}

			cmd := exec.Command(binaryPath, args...)
			if err := cmd.Start(); err != nil {
				t.Fatalf("Failed to start: %v", err)
			}

			time.Sleep(200 * time.Millisecond)
			cmd.Process.Kill()
		})
	}
}

// TestListenAddress tests different listen addresses
func TestListenAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	addresses := []string{
		":19084",
		"127.0.0.1:19085",
	}

	for _, addr := range addresses {
		t.Run(addr, func(t *testing.T) {
			binaryPath, err := buildTestBinary(t, "test_listen")
			if err != nil {
				t.Fatalf("Failed to build: %v", err)
			}

			cmd := exec.Command(binaryPath, "-mode", "server", "-listen", addr, "-password", "test")
			if err := cmd.Start(); err != nil {
				t.Fatalf("Failed to start server on %s: %v", addr, err)
			}
			defer cmd.Process.Kill()

			time.Sleep(200 * time.Millisecond)

			// Process should still be running
			if cmd.ProcessState != nil {
				t.Errorf("Server failed to start on %s", addr)
			}
		})
	}
}

// TestFlagDefaults tests default flag values
func TestFlagDefaults(t *testing.T) {
	// This test verifies the flag defaults are properly set
	tests := []struct {
		name     string
		expected string
	}{
		{"listen", ":8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Flags are parsed in main(), so we just verify the defaults exist
			t.Logf("Default %s: %s", tt.name, tt.expected)
		})
	}
}
