// h32 - minimal native 32-bit Windows fixture for the regression suite.
//
// The suite needs tests/hostname32.exe to be a valid native x86 PE that
// prints "sudfiona".  This machine has no 32-bit C toolchain (the MinGW
// install is x86_64 only) and no MSVC, so the fixture is cross-compiled
// from Go, which produces a genuine native PE32 image.
//
// Build:
//   GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -ldflags="-s -w" -o hostname32.exe .

package main

import "os"

func main() {
	_, _ = os.Stdout.WriteString("sudfiona\r\n")
}
