# RV64 M4 ArtifactStore: cache keying, integrity and the receiver boundary

*Stream `resident` (plan M4 L1), 2026-11-04. Scope: the persisted, content-addressed store that the
resident prover service (`combined-serve`, and `combined-batch`) reads its immutable setup from.
Proof format: unchanged. Every proof produced through the store is byte-identical to the M3
baseline (receipts in `vectors/reports/rv64-m4-20261104/resident/`).*

## 1. What is stored, and who may read it

| artifact | producer | stored where | read by |
|---|---|---|---|
| native setup components (CPU/truth source keys: VK section + candidate FIXED tree bulk) | `setup_cache.zig` (`RV64SUC1` v1) | `<store>/setup/<component-key>.rv64-setup` | the **prover only** |
| store manifest (`store.json`) | `scripts/rv64_m4_resident.py` | `<store>/store.json` | the harness, before the service starts |
| in-process only (not persisted in this iteration): fold-class assignment templates, fixed-authority validations of resident components, native/metadata caches, CUDA modules | the service process | RAM | the same service process |

**The receiver never reads the store.** The CPU-only receiver refuses `STWO_ZIG_RV64_SETUP_CACHE`
(`requireIndependentReceiverSetup`, `error.PersistedSetupCacheForbiddenForReceiver`), the harness
strips the variable, disables the fold class cache, hides CUDA, and **moves the store directory out of
existence for the whole receiver run** (`receive_run`: rename to `.quarantine-*`, assert absent, restore
afterwards). Every acceptance in this stream's receipts was obtained that way.

## 2. Keys

Two levels, both SHA-256, both derived from the *reader's own* identity, never from bytes found in the
store.

**Store key (directory namespace).** `/workspace/m3/store/codex-rv64-m4-resident/<key[:24]>/`:

```
key = SHA-256("rv64-m4-artifact-store/v1" || 0x00 || JCS({
        store_format, driver_sha256,      # code identity: every Zig change is a new store
        library_sha256,                   # CUDA image (kernels used to build any device artifact)
        catalogue_sha256,                 # tree hash of the AOT catalogues (generator output)
        elf_sha256,                       # the guest image
        profile,                          # conjectured128_b2_q108_p20_fold4
        field_hash }))                    # m31-circle / blake2s-merkle / om31-recursion
```

`store.json` records the components. A `--store reuse` whose recomputed key or driver hash differs from
the recorded one is **refused** (the harness exits; it never falls back to a partially matching store).
`--store fresh` deletes and recreates the namespace.

**Component key (one file per setup component).** Unchanged from #320 (`SetupCache.componentKey`):

```
component = SHA-256("rv64-gkr-setup-cache/component/v1" || SHA-256(own executable)
                    || format version || log_blowup || kind || JSON(params)
                    || ["program" || programIdentity(request)] )
programIdentity = SHA-256(elf_sha256, symbols, terminal_pc, batch/max steps, policies,
                          execution/authority/rom profiles)        # block-independent fields only
```

Geometry class (`params`: component kind, log sizes / rung) is in the key, so two blocks share an
artifact exactly when they need the same component. Block-specific data (input, expected output,
statement, witnesses) never enters any key or artifact.

## 3. Integrity on load (fail closed)

- Header (256 B) is SHA-256-sealed; the code identity inside must equal the reader's executable hash.
- VK section is SHA-256-bound in the header; the bulk section by a chunked parallel SHA-256.
- The VK's column heights must equal the heights of the columns this process just derived from the
  image (`Seam.restore` shape check); the suite identity must match.
- Any mismatch is a hard error (`SetupCacheArtifactRejected`), never a silent rebuild from a
  half-trusted file. A *missing* file is a miss and is rebuilt and persisted between requests (off the
  request wall).

## 4. Why a poisoned store cannot produce an accepted false proof

1. The receiver derives every root it trusts (source roots, fixed identity/root, recursion
   authority) from the pinned ELF and its own code, cache-disabled, store absent. Nothing the store
   contains reaches the receiver.
2. The prover's stored bulk (coefficients, Merkle layers) only changes *which* proof the prover
   emits. A wrong value yields a commitment/transcript the receiver does not reproduce, so the proof
   is rejected (liveness loss, not soundness loss).
3. Hence the trust boundary of the store is availability, not soundness. An attacker who can rewrite
   the store consistently can equally replace the driver binary, which is why the code identity is the
   executable hash.

## 5. Resident reuse inside one service (not persisted)

- `ResidentSession.setup` (one SetupCache for the life of the service): components are resident,
  pointer-stable and frozen after first build/load.
- **New in this stream:** `ResidentSession.setup_validated`. The fixed-authority binding of a resident
  component is validated once per service and reused by pointer provenance, the same rule the
  key-owner catalogue (`validated_fixed`) already uses. On any failure (e.g. the fixed cache's byte
  budget) the catalogue is cleared and the set is rebuilt once from scratch; the result is the same
  pure function either way. Proof bytes are unchanged (measured).
- Fold-class assignment templates (`outer_assignment.zig ClassCache`, default on) are process-static,
  so later requests of the service reuse them.

## 6. Catalogue drift gate

`scripts/rv64_m4_resident.py catalogue-gate` regenerates every AOT family from the current tree and
byte-compares each catalogue file (`core` = `--domain` ∪ `--grouped-domain`, `truth` = `--truth-domain`,
`rational` = `--truth-interactions`, `outer` = `--outer-native-om31`, `global` =
`rv64-global-fixtures --catalog`, `projection` = `rv64-projection-fixtures`). `truth-parts` is a
partition of `truth` whose options are not recorded; the gate checks its recorded input digests and
reports it as **not regenerated**, never as equal. `rv64_m3_pod.py build` runs the gate before every
CUDA image build and fails on drift (`--skip-catalogue-gate` is explicit and recorded in build.json).
Measured: catalogues-v3 passes (6/6 families byte-equal); catalogues-v2 fails on exactly the two
`global` public-boundary kernels that caused the 24628590 failure.

## 7. Not done / next

- Persist the fold-class templates and leaf assignment plans into the store (keyed by
  `om31_outer.classKey` + executable hash) so a cold service's first request matches a warm one.
- Cache `Image.Owner` / `ProgramAuthority.initWithRom` across requests (block-independent part), which
  is ~0.7 s of capture-overlapped work per request.
- Store pruning at milestone end (plan §6.2).
