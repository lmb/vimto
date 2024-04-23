# Execution environment

When developing new code for cilium/ebpf I usually iterate as follows:

1. Run tests using `go test -exec sudo` on the host kernel.
   Step through code using dlv (only works for some tests, sudo is cumbersome).
2. Run tests using `go test -exec vimto` on a specific kernel. This is mostly to
   mimic CI without having to push to GitHub.
3. Very rarely, debug using dlv or gdb using a specific kernel. This is to catch
   those pesky kernel bugs.

vimto should therefore support the following tasks with minimal setup or interaction
required by the user:

- Execute a set of Go unit tests against a pre-compiled kernel.
- Debugging Go unit tests with delve using a pre-comiled kernel.
- Execute Go unit tests using a kernel which is debugged by gdb.

The execution environment should be as close as possible to using `-exec sudo`
so that the "ladder of iteration" doesn't require much context switching.

- The host operating system already has all the necessary dependencies for unit tests.
- Debug tooling like gdb and delve are taken from the host filesystem.
- Kernel and modules are retrieved from an OCI image.

## Filesystems

The root filesystem is a merge of the following host paths.

| Path              | Permissions | Comment                           |
|-------------------|-------------|-----------------------------------|
| /                 | r/o         | Root of the host operating system |
| /boot, /usr, /lib | r/o         | Kernel and modules from OCI image |

The root filesystem inside the VM is writable, but changes are ephemeral and not
carried over to the host. This is because the root fs is shared by multiple VMs.
Some system relevant filesystems like /sys, /proc and so on are private to the VM.

The following paths are shared between the host and the VM:

| Path                 | Comment                                          |
|----------------------|--------------------------------------------------|
| /tmp/path/to/workdir | Temporary files used by the Go toolchain (-work) |
| /path/to/repository  | Root of the VCS repository                       |

## User and group

By default, commands execute as the current user and group. This works because
/etc is shared between the host and the VM.

It's possible to opt into running a command inside the VM as if it was invoked
via `sudo --preserve-env`. This is not straight up sudo since the user might not
have sudo privileges on the host.

## Environment variables

All variables from the environment are copied verbatim into the VM. PATH from
outside the VM does take effect when looking up binaries.

## Working directory

The working directory is preserved in the VM.
