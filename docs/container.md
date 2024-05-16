# Container format

The container (or directory) must contain a file `/boot/vmlinuz` which is used to boot the VM.

Other files and directories in the container are merged with the host filesystem
using an overlayfs mount inside the VM.

## Error: directory /lib: shadows symlink on host

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
