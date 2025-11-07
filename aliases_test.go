package main

import (
	"io"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func init() {
	// Initialize logger for tests to prevent nil pointer dereference
	logger := zerolog.New(io.Discard).With().Timestamp().Logger()
	log = &logger
}
func TestAliasLoadFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expected    AliasMap
		expectError bool
	}{
		{
			name:    "valid aliases",
			content: "user1 alias1\nuser2 alias2\nuser3 alias3",
			expected: AliasMap{
				"user1": "alias1",
				"user2": "alias2",
				"user3": "alias3",
			},
			expectError: false,
		},
		{
			name:        "empty file",
			content:     "",
			expected:    AliasMap{},
			expectError: false,
		},
		{
			name:    "file with empty lines",
			content: "user1 alias1\n\nuser2 alias2\n\n",
			expected: AliasMap{
				"user1": "alias1",
				"user2": "alias2",
			},
			expectError: false,
		},
		{
			name:    "file with whitespace",
			content: "  user1   alias1  \n\t user2\talias2\t",
			expected: AliasMap{
				"user1": "alias1",
				"user2": "alias2",
			},
			expectError: false,
		},
		{
			name:    "extra fields ignored",
			content: "user1 alias1 extra field\nuser2 alias2",
			expected: AliasMap{
				"user1": "alias1",
				"user2": "alias2",
			},
			expectError: false,
		},
		{
			name:        "single field line ignored",
			content:     "user1\nuser2 alias2",
			expected:    AliasMap{"user2": "alias2"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "aliases-*.txt")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(tt.content); err != nil {
				t.Fatalf("failed to write to temp file: %v", err)
			}
			tmpFile.Close()

			result, err := AliasLoadFile(tmpFile.Name())

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d aliases, got %d", len(tt.expected), len(result))
			}

			for key, expectedValue := range tt.expected {
				if actualValue, exists := result[key]; !exists {
					t.Errorf("expected key %q not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("for key %q: expected %q, got %q", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestLoadAliases(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "user1 alias1\nuser2 alias2"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	err = LoadAliases(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	aliasesMutex.RLock()
	defer aliasesMutex.RUnlock()

	if len(aliasesList) != 2 {
		t.Errorf("expected 2 aliases, got %d", len(aliasesList))
	}

	if aliasesList["user1"] != "alias1" {
		t.Errorf("expected user1 -> alias1, got %q", aliasesList["user1"])
	}
	if aliasesList["user2"] != "alias2" {
		t.Errorf("expected user2 -> alias2, got %q", aliasesList["user2"])
	}
}

func TestLoadAliases_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = LoadAliases(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	aliasesMutex.RLock()
	defer aliasesMutex.RUnlock()

	if len(aliasesList) != 0 {
		t.Errorf("expected 0 aliases, got %d", len(aliasesList))
	}
}

func TestLoadAliases_UpdatesExistingAliases(t *testing.T) {
	// First load
	tmpFile1, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile1.Name())

	content1 := "user1 alias1\nuser2 alias2"
	if _, err := tmpFile1.WriteString(content1); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile1.Close()

	err = LoadAliases(tmpFile1.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Second load with different content
	tmpFile2, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile2.Name())

	content2 := "user3 alias3"
	if _, err := tmpFile2.WriteString(content2); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile2.Close()

	err = LoadAliases(tmpFile2.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	aliasesMutex.RLock()
	defer aliasesMutex.RUnlock()

	if len(aliasesList) != 1 {
		t.Errorf("expected 1 alias after reload, got %d", len(aliasesList))
	}

	if aliasesList["user3"] != "alias3" {
		t.Errorf("expected user3 -> alias3, got %q", aliasesList["user3"])
	}

	if _, exists := aliasesList["user1"]; exists {
		t.Error("expected user1 to be removed after reload")
	}
}

func TestAliasLoadFile_MultipleSpaces(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "user1     alias1\nuser2          alias2"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	result, err := AliasLoadFile(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result["user1"] != "alias1" {
		t.Errorf("expected user1 -> alias1, got %q", result["user1"])
	}
	if result["user2"] != "alias2" {
		t.Errorf("expected user2 -> alias2, got %q", result["user2"])
	}
}

func TestAliasLoadFile_TabSeparated(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "user1\talias1\nuser2\t\talias2"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	result, err := AliasLoadFile(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 aliases, got %d", len(result))
	}
}

func TestAliasLoadFile_DuplicateKeys(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "user1 alias1\nuser1 alias2\nuser1 alias3"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	result, err := AliasLoadFile(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 alias (last one wins), got %d", len(result))
	}

	if result["user1"] != "alias3" {
		t.Errorf("expected user1 -> alias3 (last one), got %q", result["user1"])
	}
}

func TestAliasLoadFile_OnlyWhitespace(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aliases-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "   \n\t\t\n  \t  \n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	result, err := AliasLoadFile(tmpFile.Name())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 aliases, got %d", len(result))
	}
}
