# Publication identity reproduction

An isolated copy of the current artifact store fails a single deterministic
contract test: `putBytes` followed immediately by `resolveObject` on the same
store returns `ArtifactStoreCorrupt`. The test and failure log are retained here.
Run by copying the artifact-store Zig files into a temporary directory, adding
`publication_repro.zig.txt` as `publication_repro.zig`, and executing
`zig test publication_repro.zig -O ReleaseSafe`.

`publishTemporary` links the temporary file into the object namespace, measures
and caches its file identity, then the caller's deferred temporary unlink changes
the object's ctime. A direct filesystem experiment confirms ctime changes while
inode, size and mtime remain unchanged. The cached identity includes ctime, so
`resolveObject` rejects the store's own freshly published object.

This also supplies a concrete candidate for the historical concurrent Linux
publication failure, but that relationship is not proven: the old failure log
does not identify its underlying error, and this reproduction ran on macOS.
Do not drop ctime from identity checking to mask the mutation. Publication must
leave the accepted object identity stable, including under concurrent writers.
No production source was modified during the canonical proof source freeze.

## Isolated candidate

An atomic no-replace rename replaces link/unlink publication in the isolated
copy. Linux uses renameat2 with RENAME_NOREPLACE; macOS uses renameatx_np with
RENAME_EXCL. Unsupported filesystems fail closed. Existing object names are
never overwritten, and ctime remains part of the authenticated cache identity.
The candidate passes all 17 existing tests and three identity regressions on
macOS. All three new regressions fail against the unchanged implementation.
This candidate has not been applied to production source or qualified on Linux.

Platform contract references:
- https://man7.org/linux/man-pages/man2/rename.2.html
- https://developer.apple.com/documentation/foundation/urlresourcevalues/volumesupportsexclusiverenaming
- Xcode MacOSX SDK usr/include/sys/stdio.h (RENAME_EXCL and renameatx_np declaration).
