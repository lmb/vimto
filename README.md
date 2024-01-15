# vimto

`vimto` is a virtual machine testing orchestrator for the Go toolchain. It allows you to easily run Go unit tests using a specific Linux kernel.

```shell
go test -exec vimto -vm.kernel /path/to/vmlinuz .
```

It's possible to obtain the kernel from a container image (requires Docker).

```shell
go test -exec vimto -vm.kernel example.org/reg/image:tag .
```

`vimto` expects the kernel to be at `/boot/vmlinuz` inside the image.

## Installation

Install using the Go toolchain:

```shell
CGO_ENABLED=0 go install lmb.io/vimto
```

## Configuration

`vimto` reads a configuration file `.vimto.toml` in [TOML] format, either from the current directory or from the root of the git repository enclosing the current directory.

All available options and their values are in [testdata/default.toml](./testdata/default.toml).

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