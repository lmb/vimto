# vimto

`vimto` is a virtual machine testing orchestrator for the Go toolchain. It allows you to easily run Go unit tests using a specific Linux kernel.

```shell
go test -exec vimto -vm.kernel /path/to/vmlinuz .
```

It's possible to obtain the kernel from a container image (requires Docker).

```shell
go test -exec vimto -vm.kernel example.org/reg/image:tag .
```

Finally, you can also use a path to a directory:

```shell
go test -exec vimto -vm.kernel ./path/to/dir .
```

`vimto` expects the kernel to be at `/boot/vmlinuz` for containers and directories.
See also [Container format](#container-format).

## Installation

Install using the Go toolchain:

```shell
CGO_ENABLED=0 go install lmb.io/vimto@latest
```

## Configuration

`vimto` reads a configuration file `.vimto.toml` in [TOML] format, either from the current directory or from the root of the git repository enclosing the current directory.

All available options and their values are in [testdata/default.toml](./testdata/default.toml).

## Container format

The container (or directory) must contain a file `/boot/vmlinuz` which is used to boot the VM.

Other files and directories in the container are merged with the host filesystem
using an overlayfs mount inside the VM.

### Error: directory /lib: shadows symlink on host

This error is generated if the image contains a directory that would shadow
important directories in the host:

* /lib
* /lib64
* /bin
* /sbin

This happens when running on distributions that have completed a /usr merge. In
this case these directories are symlinks on the host. Overlaying a directory from
the image will make the symlink disappear.

To work around the issue, place files in `/usr/lib`, ... and include your own
`/lib -> /usr/lib` symlink in the image.

## Currently not supported

* Networking
* Interactive shell sessions

## Requirements

* A recent version of `qemu` (8.1.3 is known to work)
* A Linux kernel with the necessary configuration (>= 4.9 is known to work)
* Docker (optional, to fetch kernels from OCI registries)

Here is a non-exhaustive list of required Linux options:

* `CONFIG_9P_FS=y`
* `CONFIG_DEVTMPFS=y`
* `CONFIG_NET_9P_VIRTIO=y`
* `CONFIG_NET_9P=y`
* `CONFIG_NET_CORE=y`
* `CONFIG_OVERLAY_FS=y`
* `CONFIG_PCI=y`
* `CONFIG_SYSFS=y`
* `CONFIG_TMPFS=y`
* `CONFIG_TTY=y`
* `CONFIG_UNIX=y`
* `CONFIG_UNIX98_PTYS=y`
* `CONFIG_VIRTIO_CONSOLE=y`
* `CONFIG_VIRTIO_MMIO=y`
* `CONFIG_VIRTIO_NET=y`
* `CONFIG_VIRTIO_PCI=y`
* `CONFIG_VIRTIO=y`
* `CONFIG_VT=y`

[TOML]: https://toml.io/en/v1.0.0