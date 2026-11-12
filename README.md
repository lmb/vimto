# vimto

![vimto logo](logo.png "vimto: virtual machine testing orchestrator")

`vimto` is a virtual machine testing orchestrator for the Go toolchain. It allows you to easily run Go unit tests using a specific Linux kernel.

```shell
# With .vimto.toml in place:
vimto -- go test .
# Otherwise:
vimto -kernel /path/to/vmlinuz -- go test .
```

The tests are executed inside an ephemeral VM, with an [execution environment](docs/environment.md) which mimics the host.

It's possible to obtain the kernel from a container image.

```shell
vimto -kernel example.org/reg/image:tag -- go test .
```

Finally, you can also use a path to a directory:

```shell
vimto -kernel /path/to/dir -- go test .
```

`vimto` expects the kernel to be at `/boot/vmlinuz` for containers and directories.
See also [Container format](docs/container.md).

## Installation

Install using the Go toolchain:

```shell
CGO_ENABLED=0 go install lmb.io/vimto@latest
```

## Configuration

`vimto` reads a configuration file `.vimto.toml` in [TOML] format, either from the current directory or from the root of the git repository enclosing the current directory.

All available options and their values are in [testdata/default.toml](./testdata/default.toml).

## Userland

By default, the guest uses the host's root filesystem. Use `-userland` to use an
OCI image or a local directory as the guest's root instead:

```shell
vimto -userland alpine -- go test .
```

## Directory Sharing

`vimto` maps the current Git repository as well as the working directory of the
calling process into the guest automatically:

```
sd-9p-0 on /home/timo/vimto type 9p (<opts>)
sd-9p-1 on /home/timo/vimto/docs type 9p (<opts>)
```

Additional host directories can be shared with the guest using Docker-style
mappings:

```shell
vimto -volume /host/path:/guest/path -- go test .
```

If the guest path is omitted, the host path is mapped into the guest verbatim.

## Cross-architecture tests

`vimto` honours the `GOARCH` environment variable and boots a guest of a matching
architecture, using emulation if necessary:

```shell
GOARCH=arm64 vimto -userland alpine -- go test .
```

This requires the appropriate `qemu-system-*` binary on the host and uses TCG
instead of KVM, which is significantly slower. The host's binaries can't be
executed by a foreign-architecture guest, so `-userland` is required.

## Currently not supported

* Networking
* Interactive shell sessions

## Requirements

* An `amd64` or `arm64` host running Linux
* A recent version of `qemu` (8.1.3 is known to work)
* A Linux kernel with the necessary configuration (>= 4.9 is known to work)
* KVM (optional, see [VIMTO_DISABLE_KVM](docs/tips.md))

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
