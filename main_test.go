package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"rsc.io/script"
	"rsc.io/script/scripttest"
)

func TestExecutable(t *testing.T) {
	path := t.TempDir()
	cmd := exec.Command("go", "build", "-o", path, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Log(string(output))
		t.Fatal("Failed to compile binary:", err)
	}

	t.Setenv("PATH", fmt.Sprintf("%s:%s", path, os.Getenv("PATH")))

	e := script.NewEngine()
	e.Cmds["vimto"] = script.Program("vimto", nil, time.Second)

	var env []string
	for _, v := range os.Environ() {
		if strings.HasPrefix(v, "GO") || strings.HasPrefix(v, "PATH=") {
			env = append(env, v)
		}
	}

	scripttest.Test(t, context.Background(), e, env, "testdata/*.txt")
}
