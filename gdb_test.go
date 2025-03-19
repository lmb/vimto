package main

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestGdbCommandEscapeRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		escaped string
	}{
		{
			name:    "empty string",
			input:   "",
			escaped: "",
		},
		{
			name:    "plain text",
			input:   "hello world",
			escaped: "hello world",
		},
		{
			name:    "dollar sign",
			input:   "$",
			escaped: "}\x04",
		},
		{
			name:    "hash symbol",
			input:   "#",
			escaped: "}\x03",
		},
		{
			name:    "asterisk",
			input:   "*",
			escaped: "}\x0a",
		},
		{
			name:    "escape character",
			input:   "}",
			escaped: "}\x5d",
		},
		{
			name:    "high ascii",
			input:   string([]byte{0x80, 0xFF}),
			escaped: "}\xa0}\xdf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gdbEscapeCommand(tt.input)

			if tt.escaped != "" {
				qt.Assert(t, qt.Equals(got, tt.escaped))
			}

			unescaped, err := gdbUnescapeCommand(got)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(unescaped, tt.input))
		})
	}
}

func TestGdbUnescapeErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "escape at end",
			input: "hello}",
		},
		{
			name:  "run length encoding",
			input: "0* ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gdbUnescapeCommand(tt.input)
			qt.Assert(t, qt.IsNotNil(err),
				qt.Commentf("expected error for %q", tt.input))
		})
	}
}
