# Explicit offhost guest/input I/O mappings

The strict CPU qualification helper may receive explicit local `elf` and `input`
paths. Each must be absolute and hash exactly to the corresponding identity in
the original immutable producer request. The guest hash must also equal the
producer plan; the input hash must equal the selected job. Unknown mappings or
changed bytes refuse before any receiver process.

The producer plan, request, manifest, logs and proof bytes stay untouched. Only
the receiver operational copy substitutes verified local guest/input paths and
its existing worker override. The receipt records every from/to path, original
and operational request hashes, and local source-file hashes. Final admission
rechecks the immutable producer snapshot and all local guest/input bytes.

`STWO_ZIG_RV64_SETUP_CACHE` is explicitly absent from the fresh receiver's
environment. This does not change the independently qualified receiver's4GiB
in-memory recycler contract. The existing CPU-only strict endpoint rebuilds
native/outer authorities and restores every physical node, refusing new proofs
or missing/extra coverage. No producer replay or receiver trust shortcut is
introduced. Existing unmapped calls retain their path behavior.

CLI additions are `--guest-elf` and `--guest-input`. The function API accepts
`guest_paths={"elf": local_elf, "input": local_input}`. Eleven unit tests cover
existing mutation/admission guards, explicit mappings, changed mapped bytes,
unknown keys and cache exclusion; no compiled-code or GPU change is involved.
