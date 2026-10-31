package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestIsVersionArg(t *testing.T) {
	for _, arg := range []string{"--version", "-version", "version"} {
		if !isVersionArg(arg) {
			t.Errorf("expected %q to ask for the version", arg)
		}
	}

	for _, arg := range []string{"", "--help", "versions", "-v"} {
		if isVersionArg(arg) {
			t.Errorf("expected %q not to ask for the version", arg)
		}
	}
}

func TestVersionStringNamesVersionAndPlatform(t *testing.T) {
	got := versionString()

	want := "baromio-probe " + Version + " " + runtime.GOOS + "/" + runtime.GOARCH
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("expected a single line, got %q", got)
	}
}
