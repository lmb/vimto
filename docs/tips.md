# Tips

## Disable KVM

You can disable KVM by setting an environment variable:

```
VIMTO_DISABLE_KVM=true vimto ...
```

This can be useful on hosts where nested virtualisation is not available. It
will be rather slow though.

## Enable Go coredumps

Sometimes a test inside the VM crashes or panics and debugging may be difficult.
In that case you can enable collecting a core dump like so:

```
GOTRACEBACK=crash vimto -- go test ...
```

[`GOTRACEBACK`](https://pkg.go.dev/runtime) is interpreted by the Go runtime.
`vimto` will preserve the test binaries if it detects a core dump. This allows
you to collect the binary and the core dump in CI for later debugging.
