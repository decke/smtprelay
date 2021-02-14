package main

import (
	"testing"
)

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, _ := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseLine(t *testing.T) {
	var tests = []struct {
		name string
		expectFail bool
		line string
		username string
		addrs []string
	}{
		{
			name: "Empty line",
			expectFail: true,
			line: "",
		},
		{
			name: "Too few fields",
			expectFail: true,
			line: "joe",
		},
		{
			name: "Too many fields",
			expectFail: true,
			line: "joe xxx joe@example.com whatsthis",
		},
		{
			name: "Normal case",
			line: "joe xxx joe@example.com",
			username: "joe",
			addrs: []string{"joe@example.com"},
		},
		{
			name: "No allowed addrs given",
			line: "joe xxx",
			username: "joe",
			addrs: []string{},
		},
		{
			name: "Trailing comma",
			line: "joe xxx joe@example.com,",
			username: "joe",
			addrs: []string{"joe@example.com"},
		},
		{
			name: "Multiple allowed addrs",
			line: "joe xxx joe@example.com,@foo.example.com",
			username: "joe",
			addrs: []string{"joe@example.com", "@foo.example.com"},
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user := parseLine(test.line)
			if user == nil {
				if !test.expectFail {
					t.Errorf("parseLine() returned nil unexpectedly")
				}
				return
			}

			if user.username != test.username {
				t.Errorf("Testcase %d: Incorrect username: expected %v, got %v",
						 i, test.username, user.username)
			}

			if !stringsEqual(user.allowedAddresses, test.addrs) {
				t.Errorf("Testcase %d: Incorrect addresses: expected %v, got %v",
						 i, test.addrs, user.allowedAddresses)
			}
		})
	}
}
