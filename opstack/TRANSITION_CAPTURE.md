# Recovering anchored-transition material without execution

`transition_capture.py` recovers pinned witnesses, imports retained preimages,
fetches authenticated headers, and packs the existing OPD container. It never
runs Kona, an EVM, the RV64 VM, or a prover. It never installs dependencies or
reads environment variables. Run it in the existing host requirements environment
(`pycryptodome`; `rocksdict` only for RocksDB import).

The historical input named in [TRANSITION.md](TRANSITION.md) has not been
recovered. The [2026-11-09 capture receipt](../vectors/reports/rv64-opstack-performance-20261109/transition-recovery-v1.json)
records the files actually recovered and the remaining obligations. None is an
accepted derivation or a complete execution witness.

```sh
PY=/private/tmp/stwo-opstack-cpu-venv/bin/python
$PY opstack/transition_capture.py recover /private/tmp /path/to/retained-artifacts
$PY opstack/transition_capture.py probe --layer l2 --rpc https://mainnet.optimism.io
$PY opstack/transition_capture.py headers --rpc https://mainnet.optimism.io \
  --output /new/path/historical-headers
# Interrupted journals are reauthenticated from the pinned target hash.
$PY opstack/transition_capture.py headers --rpc https://mainnet.optimism.io \
  --resume --output /new/path/historical-headers
$PY opstack/transition_capture.py recent --l1-rpc https://rpc.flashbots.net \
  --l2-rpc https://mainnet.optimism.io --output /new/path/recent-candidate
```

`recover` checks the three pinned raw/compressed witness sizes and SHA-256s,
including bounded ZIP members. It never extracts an archive pathname. A match
can be copied with `--output`; existing destinations cannot be overwritten.
It also locates retained `kvformat` markers. The default walk skips credential
and build directories, does not follow symlinks, and stops at one million files.

`headers` authenticates the historical 292-header L2 parent chain from the
receipt's pinned next hash. It reconstructs canonical header RLP and verifies
both post-Isthmus output-root preimages against the independently pinned receipt.
It does not authenticate transaction JSON or assert that L1 derived these L2
headers. Each fetched header is journaled before the next request; resume rejects
altered headers or a changed pinned claim.

`recent` first pins the returned finalized L1 and adjacent L2 headers, validates
header hashes, then verifies the message-passer account's EIP-1186 inclusion proof
under the previous header's state root. It checks the authenticated storage root
against the post-Isthmus header. The resulting candidate records exact L1 anchor,
L2 hashes and previous/next output roots. RPC finality selection remains an
external trust input. The L1 origin and inbox derivation are **not yet bound**;
this is not a replacement for the historical receipt or a complete OPD input.

## Import and packaging

```sh
$PY opstack/transition_capture.py import-kv --input /path/to/retained-kv \
  --format directory --output /new/path/imported
$PY opstack/transition_capture.py pack --records /path/records.json \
  --sidecars /path/sidecars.json --output /new/path/input.opd
```

Records are JSON pairs `[full_keccak_hex, preimage_hex]`. Sidecars have exactly
`blob`, `kzg_commitment`, `kzg_proof`, with byte widths 131072, 48, 48.
`pack` authenticates every preimage, sorts records/commitments, rejects duplicate
keys and commitments, and writes the same canonical envelope/table layout as
`kona/src/{transition_input,witness}.rs`. Its optional zlib encoding can differ
from Rust miniz; no byte-identical rebuild is claimed. Parsing/container validity
never implies KZG, derivation or execution acceptance.

Kona's preimage key replaces the first digest byte with a type tag. Import only
exports type-2 Keccak entries after recomputing the full digest and checking all
31 retained key bytes. Blob hint/helper records are not guessed into sidecars;
oversized exports fail rather than silently discarding unknown records. RocksDB
is opened read-only. Do **not** instantiate the upstream `DiskKeyValueStore` on
a recovered cache: that pinned implementation destroys the database on `Drop`.

## What remains

Public access is sufficient for historical headers and recent state proofs.
The pinned historical state proof is outside the official endpoint's 10,000-block
window. A standard beacon `/eth/v1/beacon/blobs/{slot}` request returned a real
blob for the historical L1 anchor, but that response has not been bound to a
commitment with KZG. The full capture still needs:

- the execution access/hint schedule, account/storage paths, code and deletion
  siblings (historical archive state, or the equivalent recent access set);
- authenticated L1 transaction/receipt tries and the L2 reset/span context;
- all consumed blob bodies/commitments and verified standard EIP-4844 proofs;
- independent native derivation acceptance before any RV64 proof attempt.

The pinned upstream Kona host has a `--server` preimage-server-only mode, but it
still needs driven hints. Running its ordinary single-chain host would execute
the client; this utility does not invoke it. Modern beacon body availability is
not a substitute for the missing access set. No complete-witness claim should
be inferred from a successful header, account-proof or container check.

Offline tests:

```sh
$PY -W error::ResourceWarning -m unittest discover -s opstack/tests \
  -p test_transition_capture.py -q
```
