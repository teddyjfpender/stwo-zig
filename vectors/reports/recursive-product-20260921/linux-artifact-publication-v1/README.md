# Linux artifact-store publication qualification

All 20 artifact-store tests passed on both tmpfs and ext4 under x86-64 Linux
6.18.52-0-virt in QEMU TCG. The suite includes cached publication identity,
ingest/deduplication and concurrent publisher checks. The guest exited cleanly.
The exact tested artifact-store sources match the final typed-recursion checkpoint;
no repository implementation changed for this qualification.

`summary.json` records source/binary/input hashes and the cross-compilation command.
`guest.log` retains both successful suites and filesystem mount evidence.
`artifact-store-tests.gz` archives the tested executable. `run.py`, `command.json`
and `guest-init.sh` retain the guest assembly and launch procedure; its downloads
and extracted overlay remain at `/tmp/pr198-linux-publication-v1`.

The guest uses a fresh 256 MiB ext4 disk and a tmpfs mount. It has no network or
host directory mounts. Two setup attempts are retained: the first lacked BusyBox
command links; the second passed tmpfs tests but lacked an ext4 formatter library.
After completing guest dependencies, both suites passed. No test expectation or
repository source was changed.

Guest inputs came from Alpine's official v3.23 x86_64 netboot and main package
repositories. The overlay contains linux-virt modules, e2fsprogs, e2fsprogs-libs,
libblkid, libuuid and libcom_err. e2fsprogs-static was downloaded during setup but
is not used by the guest. QEMU was installed through Homebrew; it and its required
dependencies remain installed on the host. Guest preparation follows
[QEMU direct Linux boot](https://www.qemu.org/docs/master/system/linuxboot.html).
Inputs: [Alpine netboot](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/netboot/)
and [Alpine packages](https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/).

This closes the outstanding Linux runtime check for the publication repair on
these two filesystems. It is an emulated runtime check, not a CI rerun or a claim
about every Linux kernel/filesystem. The original broader goal still has 106
source-size findings; no baseline suppression was applied.
