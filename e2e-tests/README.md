# End-to-end tests

The e2e suite is a separate Go module. Each case owns a `Containerfile` and a
pair of tests:

- `<case>_test.go` with `//go:build !victim` builds the image, starts podman,
  compiles and copies the victim test binary, and verifies exported reports.
- `victim_test.go` with `//go:build victim` runs inside the container and drives
  `gofengshui` against the case fixtures.

Run the full suite as root:

```sh
sudo -E make e2e
```

The glibc base-image matrix runs as part of the suite. Use
`GFS_E2E_PULL=1` when missing base images may be pulled.

Run only the unprivileged harness/unit checks:

```sh
go -C e2e-tests test ./internal/...
```

Compile a victim test binary manually:

```sh
CGO_ENABLED=0 go -C e2e-tests test -c -tags victim \
  -o build/e2e/glibc.victim.test ./glibc
```

See `docs/DEVELOPMENT.md` for logs, artifacts, environment variables, and the
procedure for adding a new container case.
