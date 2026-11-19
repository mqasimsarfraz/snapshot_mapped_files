# snapshot_mapped_files

Snapshot files mapped by running processes with Inspektor Gadget's
`iter/task_vma` support. This includes mappings whose file descriptors have
already been closed, such as loaded shared libraries.

## Requirements

- Linux with BTF (`/sys/kernel/btf/vmlinux`), `task_vma` iterators, and
  `bpf_d_path` support for that iterator.
- An IG runtime containing the framework's `task_vma` support; stock v0.58.0
  does not support this gadget's iterator.
- Docker for the default build using the v0.58.0 builder image.
- Root privileges to run with the supplied Makefile.

Tested with the locally patched IG runtime and Linux 6.8.
The kernel must enable `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`, and
`CONFIG_BPF_ITER`.

## Build and run

```bash
# Start a process before starting the gadget:
sleep 300 &
sleep_pid=$!
PARAMS="--host --pid $sleep_pid --timeout 3 -o json" make run-local
```

Expect `mapped_files` rows for the sleep binary and its libraries. The session stops
after three seconds; clean up with `kill "$sleep_pid"`.

`make run-local` builds the current sources, then runs the unsigned local image
without pulling from a registry. Pass runtime options through `PARAMS`. To build
and run separately, use `make build IMAGE_TAG=latest`, then
`PARAMS="--verify-image=false --host" make run IMAGE_TAG=latest`.

The iterator enumerates process leaders rather than every thread. IG controls
collection cadence through data source fetch settings; "snapshotter" describes
the current-state view, not a guarantee that `ig run` exits after one snapshot.
The default fetch settings request one snapshot; the timeout bounds the session.
Use `sudo ig run ghcr.io/mqasimsarfraz/snapshot_mapped_files:latest --help` for the available collection flags.

`--verify-image=false` permits an unsigned local image; sign distributed images.
Publish explicitly after authenticating to the registry:

```bash
make push IMAGE_TAG=latest
```

## Automatic publishing

The initialization workflow and validated default-branch pushes publish
`ghcr.io/mqasimsarfraz/snapshot_mapped_files:latest` and `ghcr.io/mqasimsarfraz/snapshot_mapped_files:sha-<full-commit-SHA>` using `GITHUB_TOKEN` with
`packages: write`. Pull requests and other branches never publish. A repeated
initialization run does not republish.

Repository/organization policies must allow package writes. For an existing
package, grant this repository Actions access in the GHCR package settings.
New packages are private by default; change their visibility to allow public
pulls. To enable signing, configure the optional `COSIGN_PRIVATE_KEY` and
`COSIGN_PASSWORD` Actions secrets. Without a key, CI warns and publishes unsigned
images. See [Signing and verifying gadgets](SIGNING.md) for setup and public-key
configuration for `ig`, `kubectl gadget deploy`, and Helm.

## Understanding the output

Each snapshot produces one row per **process lifetime + mount namespace +
device/inode + permissions**. For example, the same library can appear as
`r--p`, `r-xp`, and `rw-p`: those are different mappings, not duplicate files.
`p` means private and `s` means shared.

- `mapping_count` counts distinct VMAs with the same identity and permissions.
- `mapped_bytes` sums their virtual sizes, not resident memory or unique file bytes.
- `dev_major`, `dev_minor`, and `inode` identify the backing file; paths alone
  cannot distinguish an old mapped library from its replacement.
- `deleted` means the inode has no links or a mapped path was marked deleted.
  This can indicate a library retained after an upgrade, but does not prove it.
- `fname` is a representative path. Hard-link aliases are grouped by inode;
  `path_variants` counts distinct resolved paths.
- `path_error` is a negative errno when no path could be resolved, for example
  a path longer than the 4096-byte buffer. The file identity is still reported.

All regular-file mappings are kept by default, including memfd-backed files.
Mappings without a backing file and non-regular files are skipped. To focus on
conventional shared-library names:

```bash
PARAMS="--host --shared-libs-only --timeout 3 -o json" make run-local
```

This filter matches `.so` and `.so.*` basenames, including deleted paths.
It is a naming heuristic, not ELF detection: it can miss unusually named
libraries, unresolved paths, or match files that are not libraries.

`--pid`, `--comm`, and container filters still apply. `--host` includes host
processes; without it, IG collects from containers by default. Deduplication
resets for every snapshot; snapshots are not atomic across the node.

**This is an inventory, not a vulnerability scanner.** A mapped file may never
have been executed. Identifying vulnerable versions requires build-ID/hash
and package/advisory correlation. Do not inspect only the current pathname:
it might now refer to a different inode than the mapped file.

`make test` checks formatting and runs the focused Go aggregation tests
(Go 1.26+). `make clang-format` fixes C formatting. `make build` compiles the
BPF and WASM programs and validates metadata.

## License

Userspace tooling is [Apache-2.0](LICENSE). The BPF program is
[GPL-2.0 WITH Linux-syscall-note](LICENSE-bpf.txt).
