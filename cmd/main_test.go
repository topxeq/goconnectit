package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestMain tests the main function with different command line arguments
func TestMain(t *testing.T) {
	// Test with invalid mode
	t.Run("InvalidMode", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-mode", "invalid")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("Expected error for invalid mode, got nil")
		}
		if len(output) == 0 {
			t.Error("Expected output for invalid mode, got empty")
		}
	})

	// Test with short password
	t.Run("ShortPassword", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-password", "short")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("Expected error for short password, got nil")
		}
		if len(output) == 0 {
			t.Error("Expected output for short password, got empty")
		}
	})

	// Test server mode (will not complete, just check if it starts)
	t.Run("ServerMode", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-mode", "server", "-addr", "127.0.0.1:0")
		if err := cmd.Start(); err != nil {
			t.Errorf("Failed to start server: %v", err)
			return
		}

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Kill the process
		if err := cmd.Process.Kill(); err != nil {
			t.Errorf("Failed to kill server: %v", err)
		}

		// Wait for the process to exit
		if _, err := cmd.Process.Wait(); err != nil {
			// This is expected since we killed it
		}
	})

	// Test client mode (will not complete, just check if it starts)
	t.Run("ClientMode", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-mode", "client", "-server", "127.0.0.1:12345", "-local", "127.0.0.1:0")
		if err := cmd.Start(); err != nil {
			t.Errorf("Failed to start client: %v", err)
			return
		}

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Kill the process
		if err := cmd.Process.Kill(); err != nil {
			t.Errorf("Failed to kill client: %v", err)
		}

		// Wait for the process to exit
		if _, err := cmd.Process.Wait(); err != nil {
			// This is expected since we killed it
		}
	})
}
