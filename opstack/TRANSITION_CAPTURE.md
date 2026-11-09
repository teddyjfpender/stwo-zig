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
$PY opstack/transition_capture.py probe-host --layer l2 --rpc https://mainnet.optimism.io
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

## Native-host capture preflight

The separately authorized next step is a bounded native Kona host capture, not
RV64 execution or STARK proving. `probe-host` checks the exact pinned host's
required methods before that build/run. Its `debug_executePayload` request has
empty invalid parameters only, so it tests method exposure without executing a
payload. The helper rejects any nonempty parameters for that method.

The observed official OP endpoint rejects `debug_getRawHeader`, `debug_dbGet`
and `debug_executePayload` with HTTP 403 / RPC -32601. The observed Flashbots
endpoint likewise rejects raw headers and raw receipts. In pinned
`rust/kona/bin/host/src/single/handler.rs`, `StartingL2Output` unconditionally
requests a raw L2 header before it can drive capture. No upstream `kona-host`
executable was found; compiling it against these endpoints would not fix that
first failure, so no client was run. The existing local `stwo-kona-host`
binaries implement offline `run-transition`, not online capture.

A suitable public endpoint or an audited standard-RPC hint adapter is still
needed. Header reconstruction is already available here; a full adapter also
needs authenticated transaction/receipt tries, code-hash-to-address provenance,
on-demand account/storage proofs, deletion siblings, and standard blob KZG
material. Merely suppressing unsupported witness hints cannot safely replace
those obligations.

## Standard-RPC compatibility adapter

`transition_rpc_adapter.py` removes the raw-header/raw-receipt endpoint
requirement without weakening authentication:

```sh
$PY opstack/transition_rpc_adapter.py --rpc https://rpc.flashbots.net \
  --block 0xd734e17668a3fe8ac3598bdd2e63a62f97a65ed5c3acb2c7e7fa874ed60ca96e \
  --output /new/path/l1-material
# Or serve Kona-compatible RPC for at most180seconds on loopback only:
$PY opstack/transition_rpc_adapter.py --rpc https://rpc.flashbots.net \
  --port 18545 --seconds 180 --output /new/path/l1-adapter
$PY opstack/transition_capture.py probe-host --rpc http://127.0.0.1:18545 --layer l1
```

`debug_getRawHeader` reconstructs canonical header RLP from standard block JSON,
verifies its Keccak and the requested hash/number, then retains the authenticated
preimage. `debug_getRawReceipts` reconstructs EIP-2718 receipt bytes from
`eth_getBlockReceipts`, including the optional OP deposit nonce/version fields.
It verifies exact count, order, block identity, transaction-index metadata and
rebuilds the entire hexary Patricia trie against the authenticated header's
`receiptsRoot`. It does not claim to authenticate the transaction-body JSON.
Receipt queries use the pinned block's number because one public backend returned
an empty list for the hash form; returned block hashes and the root remain
mandatory. Such an empty or inconsistent response is rejected.

The immutable trie builder passes the independent Ethereum test repository's
five trie vectors, pinned in `tests/fixtures/ethereum-trie-vectors.json`.
The actual185-receipt L1 anchor fixture and coherent status/order/block/count
mutations also pass. The loopback preflight confirms both L1 methods and L2 raw
headers now work. Unsupported state/code/execution-witness calls return an
explicit method error. No empty witness, guessed sibling or code preimage is
returned. Ordinary block/account RPC passthrough is transport only and never
enters the authenticated preimage cache.

The adapter is single-threaded, loopback-only, bounded to180seconds and10,000
requests, limits request/response bodies, bounds header caching and retained
preimage count/bytes, and exports progress on normal exit or a dispatch failure.
It has no native-host launcher, guest runner or proving entrypoint.

The remaining prefetch issue is concrete: the pinned upstream host registers
`L2PayloadWitness` as a high-level hint. `backend/online.rs` retries a failed high-
level hint before fine-grained retrieval, while `backend/util.rs` propagates an
unsupported `debug_executePayload`. The same loop **does** then try the fine-
grained hint; an unsupported high-level call does not prevent that fallback.
An explicit **host-only** prefetch-disable mode avoids repeating failed network
calls. Public-only capture additionally needs
address/slot-driven account/storage proof collection and authenticated
code-hash-to-address mapping. Unknown deletion siblings still require actual
preimages and must fail explicitly. Supplying an empty execution witness would
hide this missing capability and is intentionally unsupported here.

### Authenticated account/storage and code cache

The adapter now intercepts `eth_getProof` rather than caching transport output.
It resolves the requested header, fetches the proof by canonical block hash,
verifies account presence/absence under its state root, and verifies each exact
requested storage slot/value under the authenticated storage root. Every cached
node is a recomputed Keccak preimage from a complete verified proof. Query slots,
proof count, node sizes and retained records are bounded; duplicates and changed
values/addresses/roots reject before proof records enter the cache.

Only a verified account supplies the code-hash-to-address/block mapping.
`debug_dbGet` returns an already authenticated node or fetches `eth_getCode` for
that proven account/block and checks the entire bytecode hash before caching.
Both bare and geth `c`-prefixed code keys are supported. Unknown code hashes and
unknown deletion siblings fail explicitly without network guessing. An ordinary
empty storage value is accepted only after authenticated trie absence/inclusion;
no empty execution witness is constructed.

The real159321793 account fixture has absent slots0/2, present slot1=`0x8ab2`,
and2055bytes of code. Its full proof and code cache path pass coherent
slot/value/node/address/code-hash mutations and unknown-sibling refusals.

`capture_host/prepare.py` verifies the pinned upstream revision, exact original
source hashes and patch SHA before applying the optional-prefetch flag in a NEW
detached worktree. The patch changes only `kona-host` configuration/routing and
adds a fine-grained fallback regression; no client, guest, trie or KZG verifier
is changed. Host compilation/acceptance is a separate gate:

```sh
$PY opstack/capture_host/prepare.py --source /path/to/pinned/optimism   --output /new/path/owned-kona-capture
cd /new/path/owned-kona-capture/rust
cargo +1.95 test --locked -p kona-host --no-default-features --features single   --lib explicitly_ignored_prefetch_keeps_authenticated_fine_grained_path
```

### Bounded native capture

The separately named `capture_host/run.py` **does run the official native Kona
client and oracle**, for at most180seconds. It never runs an RV64 guest or STARK
prover. It requires the exact pinned, patched source and an already built native
host, reauthenticates the candidate headers/output-root preimages, launches two
loopback adapters with a minimal child environment, monitors decoded-KV/log
limits, and stops whole process groups. Normal interruption exports authenticated
adapter progress; a timeout is explicitly incomplete.

```sh
cargo +1.95 build --offline --locked -p kona-host --no-default-features \
  --features single --bin kona-host
$PY opstack/capture_host/run.py --source /path/to/owned-kona-capture \
  --candidate /path/to/recent-candidate --l1-rpc https://rpc.flashbots.net \
  --l2-rpc https://mainnet.optimism.io \
  --beacon https://ethereum-beacon-api.publicnode.com \
  --header-window 32 --seconds 180 --output /new/path/native-capture
```

The default header window remains1. Optional readahead fetches at most32 parents
with8threads, retaining only an exact authenticated parent chain from the
requested header. Internally valid headers from another fork are rejected from
that chain. Cache and record caps still apply. `--resume /path/to/previous-run`
requires identical source/patch/executable/candidate identities and copies bounded
Keccak/SHA-authenticated KV progress into a NEW output directory; it never
mutates the prior artifacts. No deadline is raised for a resumed attempt.

The first bounded native attempt retained4532 authenticated records,103 L1 and104
L2 headers, then hit its180second deadline with zero unknown-preimage errors.
It did not reach native acceptance. See the native-capture receipt for subsequent
attempts; filesystem allocation and decoded witness bytes are reported separately.

### Parallel authenticated L1 transport cache

`transition_transport_cache.py` precollects the ordinary L1 transaction bodies
and receipts that a serial native derivation would otherwise fetch one at a
time. It reads header ancestry by direct expected-Keccak lookup in the retained
native KV, so hundreds of thousands of unrelated blob-field/helper entries never
enter the OPD ordinary-record counter. At most8RPC requests are in flight;
responses, file sizes, candidate count and total transport bytes are bounded.

Each completed entry authenticates the header, every transaction hash, the
entire transaction trie, and the entire receipt trie before publication. Legacy,
EIP-2930/1559/4844/7702 and OP deposit encodings have explicit layouts. Coherent
payload edits plus a recomputed cache-file SHA still fail the header's trie root.
The sealed cache is bound to the exact pinned candidate identity and contains
no acceptance flag. Native Kona still performs its original checks.

```sh
$PY opstack/transition_transport_cache.py --rpc https://rpc.flashbots.net \
  --kv /path/to/retained-native-run/kv --candidate /path/to/recent-candidate \
  --workers 8 --count 128 --seconds 180 --output /new/path/l1-transport-cache
# Add these flags to the next bounded native run:
# --transport-cache /new/path/l1-transport-cache --resume /path/to/retained-native-run
```

The actual103-block window26378527..26378629 completed in120.6seconds with zero
errors and131.57MB of transport JSON, below the256MiB cache cap. This is distinct
from the native witness's64MiB decoded-KV budget and4GiB filesystem-allocation
budget. Blob fields can contribute approximately4096entries per blob and are
not ordinary OPD Keccak records. Export must reconstruct full authenticated
sidecars, including standard KZG proofs, rather than pack those fields as
ordinary records or manufacture missing proofs.

The recent next origin is now independently pinned as26378577/hash
`a318027d823bee7ebe41f143d57c441bc6c461ca5c7af237871b7ae023b152a1`.
It is decoded from the authenticated Jovian L1-info deposit at transaction zero,
checks the fixed depositor/predeploy and L1-info source-hash domain, and appears
in the authenticated parent chain from the selected L1 anchor. This completes
claim framing, not derivation or proving acceptance.

### Native KV sidecars and standard KZG

`transition_kv_export.py` treats the native namespaces separately. It authenticates
Keccak/SHA entries, reconstructs each blob's4096field elements using Kona's exact
bit-reversed roots, retrieves the standard proof from the separate4096th proof
slot, rejects unowned/missing/noncanonical fields, and runs the independent
`capture_host/blob_check` native checker before publishing sidecars. It removes
only exact, identified blob-oracle helper preimages from ordinary records.
The resulting material still requires the independent native transition verifier;
removing an actually needed preimage cannot yield acceptance.

```sh
cargo +1.95 build --offline --locked --release \
  --manifest-path opstack/capture_host/blob_check/Cargo.toml \
  --target-dir /tmp/op-capture-kzg
$PY opstack/transition_kv_export.py --kv /path/to/native-capture/kv \
  --checker /tmp/op-capture-kzg/release/op-capture-kzg \
  --trusted-setup /path/to/c-kzg-2.1.8/src/trusted_setup.txt \
  --output /new/path/exported-material
```

The checker verifies the standard trusted-setup SHA before parsing those same
bytes, recomputes every blob commitment, and verifies every standard EIP-4844
proof. All15actual captured blobs passed. Flipped blob/proof bytes, swapped
otherwise valid proofs, truncation, excess count, duplicate commitment and a
changed setup byte were rejected. No RV64 execution or STARK proof is involved.
The exported material has55770ordinary records and15sidecars; complete-witness,
derivation and physical-proof acceptance remain separate gates.

### Durable code provenance during resumed capture

A30second diagnostic stopped at the first failure after13.8seconds and isolated
one missing code hash. The native KV already held its account proof, so a resumed
client could read the account without triggering another RPC proof. The fresh
adapter had lost the address that supplied that code hash. Its refusal was
correct; retrying an unknown code request could not reconstruct that address.

The adapter now exports bounded account-proof provenance. A resumed adapter
re-verifies every mapping against the independently pinned prior header before
using its address/block for `eth_getCode`. Claimed hash/address changes and a
changed header reject; code bytes still require their exact hash. A bounded
failure ledger distinguishes upstream transport errors from static validation
errors and records only public hex proof selectors, never arbitrary RPC bodies
or endpoint credentials.

For older captures with no provenance file, explicit
`--refresh-missing-code-provenance` inspects only account leaves reachable from
the pinned prior state root. It verifies every cached node hash, skips unknown
subtrees, and identifies nonempty code hashes that have neither a verified code
preimage nor authenticated address provenance. Only those account-leaf cache
entries are omitted from a NEW resumed cache. Kona's existing address-bearing
account hint then refetches the leaf normally. No state value or preimage is
manufactured and the initial state root never changes. Future provenance is
retained. The default does not evict anything.

On the actual capture, this authenticated inspection visited7787nodes and100
account leaves and identified exactly one missing-code leaf, hash
`69d3d3bddc13f6c45dcd230e2a0aac31b4366f9473d5b347c925ec0539216216`.
The coherent-root tests exclude unrelated valid-looking leaves and reject
corrupted cached hashes. `--stop-on-adapter-failure` ends diagnostic capture at
the first surfaced error rather than exhausting the deadline blindly.
