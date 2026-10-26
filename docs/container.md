# Container format

The container must contain one of these files in order to boot the VM.

1. `/boot/vmlinux`
2. `/boot/vmlinuz`

The first existing file is used.

Modules at `/lib/modules` or `/usr/lib/modules` in the container are bind
mounted to `/lib/modules` in the guest, so that tools like `modprobe` work
regardless of the layout of the guest's root file system. All other files and
directories in the container are merged over the guest's root file system using
overlayfs.

Note: The container should not ship top-level usrmerge symlinks like `lib ->
usr/lib`: overlayfs doesn't merge a symlink with a directory, so the symlink
would shadow the contents of the root file system. Place files in `/usr/lib`
etc. instead. For backwards compatibility, a top-level `lib` symlink is removed
from pulled kernel images.
