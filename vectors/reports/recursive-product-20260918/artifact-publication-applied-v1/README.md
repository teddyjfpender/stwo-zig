# Stable artifact publication identity

Applied the isolated reproduction's fix at the shared artifact-store owner.
Publication atomically renames the completed temporary file without replacing
an existing object, then measures and caches the final identity. This removes
the post-publication hard-link cleanup that changed ctime and invalidated a
fresh cache entry. ctime, size, inode and mtime checks remain intact. Existing
digest-name conflicts are still measured and rejected if their content differs.

Linux uses renameat2/RENAME_NOREPLACE; macOS uses renameatx_np/RENAME_EXCL.
Unsupported kernels/filesystems fail with AtomicPublicationUnsupported instead
of using a replacement or hard-link fallback. The package README records this
platform contract. No public API or protocol identity changed.

Three regression cases cover immediate cached resolution, ingested snapshots
and deduplication across stores. All three fail on the previous implementation
and pass with the fix. The concurrent publisher test additionally resolves both
stores' cached identities after completion and surfaces underlying errors.

Validation on macOS: 20 artifact-store tests, eight Metal-session consumer tests,
and 45 package/workspace tests pass. Formatting and diff checks pass. The exact
applied tests cross-compile to a static x86_64-linux-musl executable; no Linux
runtime is available locally, so neither Linux runtime qualification nor the
historical Linux CI failure's exact cause is claimed.

The preceding canonical typed-RISC-V/recursion checkpoint remains evidence for
its frozen source. This subsequent artifact-store repair has the scoped tests
above; no complete proof rebuild was repeated. The broader original baseline
goal remains open, including Linux runtime qualification and source-size findings.
