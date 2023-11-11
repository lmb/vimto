Allow running Go tests under a different kernel, with the same userspace. Usage:

    go test -exec gotestvm -vm.kernel /path/to/vmlinuz .

# Execution

Behind the scenes, Go compiles a test binary into a temporary directory and then
executes `gotestvm /path/to/test ...`. `gotestvm` prepares an initramfs which
contains the binary itself as `init` and launches qemu using the two.

If `gotestvm` is run as pid 1 it switches into init mode instead of providing
the regular user interface.

# Command line flags
The go test runner passes flags following the test binary itself, prefixed with
`test.`.

```
gotestvm /path/to/test -test.vm.kernel ...
```

We have to skip the first argument, and then look for `-test.vm.` prefix. Unknown
`vm.` flags should be rejected.

Q: how do we allow setting -help on plain `gotestvm`?
