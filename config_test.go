package main

import (
	"testing"
)

func TestSplitProto(t *testing.T) {
	var tests = []struct {
		input string
		proto string
		addr  string
	}{
		{
			input: "localhost",
			proto: "",
			addr:  "localhost",
		},
		{
			input: "tls://my.local.domain",
			proto: "tls",
			addr:  "my.local.domain",
		},
		{
			input: "starttls://my.local.domain",
			proto: "starttls",
			addr:  "my.local.domain",
		},
	}

	for i, test := range tests {
		testName := test.input
		t.Run(testName, func(t *testing.T) {
			pa := splitProto(test.input)
			if pa.protocol != test.proto {
				t.Errorf("Testcase %d: Incorrect proto: expected %v, got %v",
					i, test.proto, pa.protocol)
			}
			if pa.address != test.addr {
				t.Errorf("Testcase %d: Incorrect addr: expected %v, got %v",
					i, test.addr, pa.address)
			}
		})
	}
}
