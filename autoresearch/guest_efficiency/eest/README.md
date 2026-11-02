# EEST blockchain tests on both RV64 Ethereum guests

`eest.py` runs the Ethereum execution spec tests (EEST) blockchain fixtures
against our two RV64 Ethereum clients:

- **evmone**: `benchmarks/guest_runtime/ethereum/client_evmone` (ziskethone +
  evmone v0.24), built in its EEST variant (below). The RV64 guest is the v3
  client (`build.py --profile v3`, default v3 service set, `ethereum_services_v3`)
  unless `--evmone-profile admitted` selects the v2 client of the v1 receipt.
- **rust**: `stateless-validator-reth` at `a134a621` with the
  `ethereum-services-v2-lean` patch set (`benchmarks/guest_runtime/ethereum/rv64`).

Receipts: `vectors/reports/rv64-ethereum-20261101/eest-guests-v1.json` (both clients,
admitted v2 evmone), `vectors/reports/rv64-ethereum-20261102/eest-guests-v2.json`
(evmone v3 client only).

## Route

Our guests read a canonical SSZ `StatelessInput` (new-payload request, execution
witness, chain id, public keys). EEST does not ship that for the forks the
guests support: the `tests-zkevm@v21.0.6` release carries `statelessInputBytes`
only for its EIP-8025 tests, all filled for Amsterdam, which neither guest
accepts. So the inputs are generated here:

1. **Fixtures.** `tests@v21.0.2` (`fixtures.tar.gz`, 939,189,561 bytes, sha256
   `e2fa7ea2…79ed9`, pinned in `eest.py`). Only `blockchain_tests` and
   `blockchain_tests_engine` under the in-scope directories are extracted.
2. **Witness.** `witness_gen/` is a crate built inside the pinned
   `paradigmxyz/stateless` workspace (`a134a621`, the revision the Rust guest
   links). It replays each test on reth as that workspace's `ef-tests` crate
   does, checks reth's post-state root against every fixture header, and
   records each valid block's witness in reth's canonical mode (the
   `projects/zkevm` spec format).
3. **Payload request.** Taken from the matching `blockchain_tests_engine` test
   (`engine_newPayloadV4` params: payload, versioned hashes, beacon root,
   execution requests), i.e. what a consensus client sends. Requests are
   decoded into the SSZ deposit, withdrawal and consolidation lists. Without an
   engine counterpart the request is rebuilt from the block and reth's requests.
4. **Invalid blocks** (`expectException`) get a witness of the whole parent
   state (every account and storage trie node, every code, up to 256 ancestor
   headers), so a guest has all it needs and must reject on the block itself.
   As a control, every valid block is also emitted with such a full-state
   witness (`-fw` inputs); both clients must accept those.
5. **Expected output** of a valid block: `request_root | 0x01 | chain id 1 |
   schema id`, computed from the request alone. A guest reproduces it only if
   it re-derives the fixture's block hash, state root, receipts root and
   requests hash. The generator also runs the upstream `stateless-validator-reth`
   natively on each input as a reference (`reference_output`).

The schema id gives the fork (`Prague` 0x11, `Osaka` 0x12, `BPO1` 0x13, `BPO2`
0x14), taken from the network's schedule at the block's timestamp. The Rust
guest already activates every fork up to the schema's at genesis.

**evmone EEST variant.** The production client derives the fork and blob
schedule from mainnet timestamps and rejects a schema that disagrees, so it
would reject every EEST block (synthetic timestamps). `build.py --eest` adds
`-DZEG_FORK_FROM_INPUT -DSTWO_EEST_FORK_FROM_SCHEMA`: the fork and blob
parameters then come from the schema id, as in the Rust guest. That is the only
difference (two `#if` blocks in `glue/stwo_client.cpp`); the default build is
unchanged. The EEST variant must never be deployed.

## Tiers

- **T1 host.** `client-evmone-host-eest` (native build, emulated services) and
  `rust_host/` (the Rust guest's `run_stateless_guest` with the same `[patch]`
  set; the RV64-only Keccak/secp ECALL paths are not in a host build).
- **T2 guest.** The RV64 ELFs (`client-evmone-v3-eest.elf` on the
  `ethereum_services_v3` profile, or `client-evmone-admitted-eest.elf` on
  `ethereum_services_v2`, and the unchanged production
  `ethereum-rv64-services-v2-lean.elf` on `ethereum_services_v2`) on
  `rv64-ethereum-execution`, checking the exact
  43-byte output. `--guest-sample per-file` runs only the first valid and first
  invalid block of each fixture file; the default runs everything.

## Categories (per block, client and tier)

| Category | Meaning |
|---|---|
| `PASS` | valid block, exact expected output |
| `PASS_NEG` | invalid block, rejected (abort / trap / `successful_validation=false`) |
| `FAIL` | valid block rejected or wrong output (completeness) |
| `FAIL_NEG` | invalid block accepted (soundness) |
| `ERROR` | timeout, step limit or executor error (not a verdict) |
| `NA_POS` / `NA_NEG` | no SSZ input can represent the block (reason recorded: e.g. a partial request record, an extra-data field over 32 bytes, a code over 64 KiB) |
| `OUT_OF_SCOPE` | a Cancun block of `CancunToPragueAtTime15k` |
| `GEN_FAIL` | reth itself rejected a valid fixture block (no input) |

Out of scope for the whole run (not extracted): every pre-Prague network
(`for_frontier` .. `for_cancun`, `for_paristoshanghaiattime15k`,
`for_shanghaitocancunattime15k`), Amsterdam and its BPO variants (`for_amsterdam*`,
`for_bpo2toamsterdamattime15k`): both clients accept only the `ElectraFulu`
request shape. `blockchain_tests_engine_x`, `blockchain_tests_sync`,
`state_tests` and `transaction_tests` are other formats of the same cases.

## Commands

```sh
E=autoresearch/guest_efficiency/eest/eest.py
C=/path/to/cache   # ~6 GB: fixtures, stateless workspace, builds
W=/path/to/work    # ~10 GB of SSZ inputs for the full run

python3 -I $E fetch   --cache $C
python3 -I $E build   --cache $C [--evmone-cache DIR]
python3 -I $E convert --cache $C --work $W --tmpdir /Volumes/stwo-eest-ram/tmp
python3 -I $E host    --cache $C --work $W
python3 -I $E guest   --cache $C --work $W [--guest-sample per-file]
python3 -I $E receipt --cache $C --work $W [--out RECEIPT.json]
# --filter SUBSTR restricts any step to matching fixture paths, --jobs N (<= 12),
# --clients evmone,rust (default both), --evmone-profile v3|admitted (default v3)
```

Every step resumes: finished fixture files are skipped. The generator's reth
databases are fsync-bound on macOS (`F_FULLFSYNC` on each small commit); a RAM
disk for `--tmpdir` makes conversion about 8x faster:

```sh
DEV=$(hdiutil attach -nomount ram://4194304 | awk '{print $1}')   # 2 GiB
diskutil erasevolume HFS+ stwo-eest-ram $DEV
# ... run ...
hdiutil detach $DEV
```

Toolchains: Rust stable (generator), `nightly-2026-08-08` (Rust host and
guest), zig 0.15.2 (evmone, executor). Sources fetched at pinned commits:
`paradigmxyz/stateless` `a134a621` (its own lockfile pins reth `3d270d93`),
and the evmone client's pins in `client_evmone/build.py`.

## Limits

- Valid-block witnesses are reth's canonical-mode witnesses. A client that
  needs a node reth leaves out fails as `FAIL`; the receipt keeps the reason.
- Invalid blocks get a full-state witness, so a rejection is never caused by a
  missing node (the `-fw` control shows the full-state witness is accepted on
  every valid block). The receipt also tallies the evmone host's rejection
  reasons.
- Engine fixtures do not carry blocks whose RLP reth cannot decode; those are
  `NA_NEG` unless the engine fixture has a payload for them.
- The schema-from-fork model validates each block in isolation; the guests
  never see the previous block's fork. EEST transition tests still pass because
  each block's rules depend on its own timestamp.

## Results (tests@v21.0.2, 2026-11-01)

4,723 fixture files, 34,561 tests, 41,286 blocks: 37,295 valid and 3,543
invalid blocks became inputs (8 valid ones with a full-state witness, because
reth itself disagrees with the fixture on them); 416 Cancun blocks are out of scope and 32 invalid
payloads cannot be expressed as SSZ requests. Every input ran on both tiers
(T2 is the whole corpus, not a sample), plus 37,287 full-state-witness controls.

| | valid PASS | valid FAIL | invalid rejected | invalid accepted | error |
|---|---:|---:|---:|---:|---:|
| evmone host | 37,095 | 200 | 3,543 | 0 | 0 |
| evmone RV64 | 36,942 | 349 | 3,543 | 0 | 4 |
| rust host | 37,287 | 8 | 3,539 | **4** | 0 |
| rust RV64 | 37,284 | 10 | 3,539 | **4** | 1 |

Rust's 8 valid-block failures are `withdrawals_credited_before_request_system_call`
(reth disagrees with the fixture); its 4 accepted invalid blocks are
`SYSTEM_CONTRACT_EMPTY`. Every failure group is classified in
`failure-classification.json`, which the receipt embeds. Conversion took 7 min
(RAM disk), host 6 min, guest 85 min at 6 jobs on an M-series Mac.

Two evmone witness-dependence bugs found here are fixed (EIP-7702 designator
code, trie delete ordering: 1,111 blocks); the production admitted ELF still
reproduces all 15 basket blocks exactly (8.500 scored instructions/gas).

## Results v2 (evmone v3 client, 2026-11-02)

Re-run of the evmone client only (Rust unchanged, not re-run) on
`codex/rv64-guest-efficiency` @ `2490495dd` (patches 0001-0029), guest
`--profile v3` with the default service set on `ethereum_services_v3`. The
conversion reproduced v1 exactly (same counts and reference results).

| | valid PASS | valid FAIL | invalid rejected | invalid accepted | error |
|---|---:|---:|---:|---:|---:|
| evmone host | 37,295 | 0 | 3,543 | 0 | 0 |
| evmone RV64 v3 | 37,294 | 1 | 3,543 | 0 | 0 |

Full-state-witness controls: host 37,287/37,287, guest 37,286/37,287. The one
failure (and its control) is `stStaticCall/static_call1_mb1024_calldepth` block 1:
~1024 frames x 1 MB of EVM memory (host peak RSS 600 MB) exceed the 212 MiB guest
heap; the Rust guest fails it too. No regression against v1; the four BLS MSM
blocks that hit the 10^10 step limit in v1 now finish in 2.0-3.0e9 instructions
(16.9-51.5 instr/gas). The unmerged `codex/rv64-ge-client3` (patch 0030, secp on
arith256_mod) gives identical verdicts and outputs on all 78,125 runs with 4.46%
fewer instructions (`forward_check_client3` in the receipt). Conversion 4 min
(RAM disk, 10 jobs), host 3 min, guest 13 min (12 jobs).
