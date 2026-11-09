# RFC draft: five waist packages at 1.0.0-rc.1

Status: exact transaction prepared for the user-directed D1 target; final 1.0.0
and Phase 1 exit remain unapproved and incomplete. Slice: [#354](https://github.com/teddyjfpender/stwo-zig/issues/354).
RFC: [#355](https://github.com/teddyjfpender/stwo-zig/issues/355).
Owner roles: `protocol-core`, `backend-contracts`, `prover-api`, `proof-wire`,
`circuit-recursion`; named accountable owner for every role: `@teddyjfpender`.
Census source: `27ed1d34894c554fcdaf91af3c4eae331ea242ac`.

## Exact transaction

| Existing package and path under `src/waist/` | Contract/manifest version before | Version after | Public ledger entries | Direct declared consumers |
| --- | --- | --- | --- | --- |
| `stwo_core`, `core` | `0.1.0` | `1.0.0-rc.1` | 29 | 24 |
| `stwo_backend_contracts`, `backend` | `0.1.0` | `1.0.0-rc.1` | 15 | 9 |
| `stwo_prover_api`, `prover_api` | `0.1.0` | `1.0.0-rc.1` | 23 | 12 |
| `stwo_proof_wire`, `proof_wire` | `0.2.0` | `1.0.0-rc.1` | 21 | 3 |
| `stwo_circuit_recursion_wire`, `recursion_wire` | `0.1.0` | `1.0.0-rc.1` | 11 | 2 |

For each row change only `package.contract.json.version`, the matching
`build.zig.zon` version and the README version fact. Preserve the actual recursion
package/module name `stwo_circuit_recursion_wire`; the plan's shorter descriptive
name is not a module-renaming instruction. Keep every manifest fingerprint,
minimum Zig version, public module, API ledger entry, signature/invariant test
reference, dependency path, injection and CI command unchanged.

The existing checker currently accepts only numeric `major.minor.patch`.
Before the metadata edit add strict valid/invalid prerelease cases to its
existing test module, then extend only that version parser to admit valid
SemVer prerelease identifiers, including `1.0.0-rc.1`. Numeric identifiers must
not acquire leading zeroes; empty identifiers, extra punctuation, missing base
components and non-string versions remain invalid. Keep plain numeric versions
valid. Contract/manifest/README equality remains exact, including the prerelease.
No permissive fallback, schema v3 or separate version registry is proposed.

## What the candidate declares

This records a candidate freeze of the existing provider/consumer surface for
review under ENGINEERING_STANDARDS.md sections 4 and 6 and plan section 7.2.
It does not certify final stability, protocol soundness, hardware validation,
performance, production release admission or completion of any separate item.
The user's D1 target expressly precedes the Phase 1 exit version `1.0.0`.
Later contract edits still need an RFC, executable specification and the
applicable compatibility/version review; the RC label grants no waiver.

| Separate obligation | State and boundary of this transaction |
| --- | --- |
| D2 boundary error codes | No new global `Error` or u16 table; existing error tags, meanings and refusal classes remain exact. Stable boundary mapping needs its own contract transaction. |
| D3 consumer-driven contracts | Existing provider signature/invariant tests remain mandatory. They do not establish registration and execution of every consumer-owned CDC suite. |
| D4 property laws | Candidate PR #350 is separate, with integrated hosted acceptance pending; its source and gates are not absorbed here. |
| D5 per-package budgets | Existing repository budget stays enforced; generated package budgets and CI enforcement remain a separate item. |
| API-diff semver gate | Current checker verifies true exports, ledger and manifest facts; it does not yet compare historical API diffs to require major/minor bumps. This RC does not claim that planned gate exists. |
| Other Phase 1 membership moves | Existing `cairo_air_layout`, `circuit_proof_shape`, `test_utils` and all other core exports remain present. Moving them later needs their own compatibility/forwarding transaction. |

## Existing dependency and version consumers

The contract owns the version. The four other waist packages depend on core by
`../core`; core has no declared package dependency. Every declared consumer edge
is a local Zig `.path` plus the same relative path in its contract. There are
no semver dependency ranges or remote package hashes to rewrite. Root
`build.zig.zon` retains its own `0.1.0` version and all five path bindings.
No consumer package is bumped merely because its provider's metadata changes.

Core's 24 direct consumers are the other four waist packages; CPU/CUDA/Metal
backends; the prover engine; Cairo/circuit/RISC-V/SM83 frontends; Cairo
CPU/CUDA/Metal, circuit CPU/Metal, native CUDA, RISC-V CPU/CUDA/Metal and SM83
CPU/Metal integrations; and native examples. Backend contracts' nine are those
three backends, prover engine, Cairo frontend, Cairo CUDA/Metal, native CUDA and
RISC-V CUDA integrations. Prover API's twelve are Metal backend, prover engine,
Cairo/RISC-V/SM83 frontends, Cairo CPU/Metal, circuit CPU/Metal, RISC-V CPU/CUDA
integrations and native examples. Proof wire's three are circuit CPU, native
CUDA and native examples. Recursion wire's two are circuit CPU and RISC-V CPU.
These are dependency consumers, not a claim that D3 CDC registrations exist.

Recursion wire's existing `interop_cairo_prover_parameters` and
`interop_felt_json` injections remain exact; no new cross-waist dependency or
public alias is added to hide them. Dependency graph/ownership projections and
reverse-dependency focused lane selection remain unchanged.

Version readers found in the repository:

- `check_package_workspace.py` parses the version and checks exact manifest and
  README facts; this is the one parser that needs prerelease support.
- `package_release.py` uses that same loader and copies the version verbatim to
  deterministic archive prefixes, manifests and index entries. Distribution
  policy is independent: recursion wire remains `internal`, and all deferred
  GPU packages remain deferred. This transaction publishes no archive or tag.
- `ci_package_graph.py` and direct protocol command construction read the same
  contracts for names, public module roots and local dependency paths; they do
  not resolve versions or introduce version constraints.
- Existing package-workspace/release/downstream tests exercise these readers.
  Their generic `0.1.0`/`0.0.0` fixtures stay valid and unchanged.

## Frozen ledger identities

The following SHA256 values cover UTF-8 JSON of each sorted `api_surface` array
using separators `(',', ':')`; this is review evidence, not a new source pin.
Implementation must preserve every array element and all corresponding source
exports/signatures, not merely these counts.

| Package | Existing ledger SHA256 |
| --- | --- |
| `stwo_core` | `dc78c18b8750140ed8414c6e4d52ec161d8b45b6c54882a7e151bb56fdc0bfcb` |
| `stwo_backend_contracts` | `e8211b59d6ed51c8ddbf3bbaf04c8bcc64b71df567553f4c13ab6d3c5b20fc24` |
| `stwo_prover_api` | `0d2d114bbca5e2b0e527ae7f0fa264c59484a810cd7ea3746bc4129157dd7f2f` |
| `stwo_proof_wire` | `e53c2c65651a9edd6c2c507497a3c218d4013b21e35bda606bd559018db6aad8` |
| `stwo_circuit_recursion_wire` | `20f5f372e0ae5903c9de381e25c87977df92bbe5ff120a0b1360297addbd3a9f` |

## Executable acceptance and rollback

Add parser tests first through `scripts/tests/test_package_workspace.py`, then
apply the five metadata triples together. Run the existing workspace zero gate,
package-release/downstream/graph contracts and strict unchanged API/dependency
comparison under 1 GiB memguard. Preserve the existing hosted Debug/ReleaseFast
provider, CPU proof/frozen-byte and focused consumer commands, discovery floors
and error/negative corpus. No local heavy compile or GPU run is required.

Compare every `.zig` source in the five package trees before/after byte for byte;
all codec, field, transcript, error and public consumer signatures remain exact.
Only `.zon` version strings change. Frozen fixtures/pins remain byte-identical.
Do not record pending hosted qualification as PASS.

Pre-edit budget: runtime and API source +0/-0/net0; total code target0 with a
bounded +40 net Python/parser-test allowance only if needed for strict prerelease
handling. Flags +0/-0, scripts/launchers +0/-0. Report ten metadata version
substitutions and the budget entry as configuration; five README facts and this
RFC as documentation. File moves and unrelated checker changes are excluded.

Before publication revert this transaction as one unit if a gate fails. No
published release, tag or archive is retired. Final `1.0.0`, new process/wire
error ABI, CDC registration, package budgets, changed proof bytes, protocol
revision and D2/D3/D5 completion are outside this decision.
