// vminit is the init process of the virtual machine started by vimto.
//
// It is built as a statically linked binary for each supported architecture
// and embedded into vimto, see vminit.go in the root package.
package main

import (
	"fmt"
	"os"

	"lmb.io/vimto/internal/guest"
)

func main() {
	if err := guest.Init(guest.RealSyscaller{}, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
