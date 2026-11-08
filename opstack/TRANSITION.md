# Replaying the anchored OP Mainnet transition

The 2026-11-08 [receipt](transition-159257842-receipt.json) records a complete historical transition from OP Mainnet block 159257841 to 159257842 using Ethereum L1 anchor 26367973. The native Kona verifier and the RV64 guest independently reached the same public result. The RV64 execution report is a diagnostic replay; it does not contain a STARK proof.

The receiver pins Ethereum chain 1, OP Mainnet chain 10, the L1 anchor number and hash, and the preceding and next L2 output roots. Kona walks authenticated L1 ancestry, consumes inbox data whose commitments are in the L1 transaction trie, verifies the EIP-4844 blobs, derives the L2 payload, and executes it against the authenticated prior state. The guest publishes a 43-byte `OD` output binding the checkpoints, L1 origin, derived payload, and computed L2 block hash. The same payload can be sent independently to the execution guest; its separate 43-byte `OP` output is in the receipt. Anchor selection and finality are external inputs to the receiver: replay authenticates ancestry back from the selected anchor and does not itself prove beacon finality.

## Reproduce the result

The retained `OP-Mainnet-Proof-Reproduction.zip` contains `transition-159257842/input.opd`, a 21,530,433-byte witness with SHA-256 `bae3a618357459a8a136b16c300e395841aa7c4f1c061886f71be8812eca4b25`. Extract it and set `INPUT` to that file. Build from the repository root with the pinned Rust nightly and Zig 0.15.2 on `PATH`:

```sh
BUILD=/tmp/kona-transition-replay
python3 opstack/build.py --variant transition --artifacts "$BUILD"
"$BUILD/host" run-transition "$INPUT" > "$BUILD/native.json"
```

The optional last argument to `run-transition` is a new file path for the authenticated-read trace, which also contains an execution fixture derived from the accepted L1 inputs. The report must match the `statement` object in the dated receipt. To run RV64 against the independently pinned `OD` output, construct the runner configuration from the built ELF:

```sh
python3 - "$BUILD" "$INPUT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from scripts.riscv64_csp_compare import elf_info

build, witness = map(lambda arg: Path(arg).resolve(), sys.argv[1:])
elf = build / 'guest.elf'
receipt = json.loads(Path('opstack/transition-159257842-receipt.json').read_text())
assert json.loads((build / 'native.json').read_text()) == receipt['statement']
sha256 = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha256(witness) == receipt['input']['sha256']
_, symbols, _ = elf_info(elf)
names = ('input_start', 'input_end', 'halt_flag', 'output_len', 'output_data',
         'output_end', 'stack_bottom', 'stack_top', 'heap_start', 'heap_end')
config = dict(elf=str(elf), input=str(witness), elf_sha256=sha256(elf),
              input_sha256=sha256(witness), expected_output=receipt['od_public_output'],
              engine='fast', max_steps=10_000_000_000, execution_profile='ethereum_services_v3',
              symbols={name: symbols['__' + name] for name in names})
(build / 'rv64-config.json').write_text(json.dumps(config) + '\n')
PY
"$BUILD/rv64-execution" "$BUILD/rv64-config.json" > "$BUILD/rv64.json"
```

Check `status: completed`, `verified_output: true`, and the exact output in the receipt. Elapsed time and ELF identity can vary with the build environment. Use `--variant transition-sha` for the separately measured guest that calls the existing SHA-256 service. On the retained input it completed in 4,515,634,562 instructions; pruning to the authenticated read set reduced the input to 18,871,913 bytes and the execution to 4,317,643,221 instructions, with identical native and RV64 outputs. The proof gate is deterministic: `conjectured128_b2_q108_p20_fold4` admits at most 256 native proofs and CPU traces of at most `2^22` rows. A [subsequent replay](../vectors/reports/rv64-opstack-transition-20261108/) used an uncompressed form of the pruned witness and direct canonical BLS scalar decoding. It completed in 3,250,596,756 instructions, requiring at least 776 CPU proofs before any Keccak, RAM, or other service proofs. The separately permitted 23-bit public boundary does not raise the CPU trace limit. No complete proof or recursive receipt is claimed for this transition.

## Reconstruct the witness from chain data

The retained witness makes replay independent of archive endpoint availability. For a fresh capture, the input boundary is `host pack-transition CLAIM.json RECORDS.json SIDECARS.json INPUT.opd`. `CLAIM.json` takes `anchor` and `next_origin` objects with `number` and `hash`, plus `previous_number`, `previous_root`, `next_number`, and `next_root`. `RECORDS.json` consists of `[keccak256_digest, hex_bytes]` pairs, where the first member is the Keccak-256 hash of the decoded second member. `SIDECARS.json` contains `blob`, `kzg_commitment`, and `kzg_proof` hex fields; the packer sorts the sidecars by commitment. The exact archive capture used these steps:

1. Pin L1 block 26367973 by hash and confirm it is below the finalized height from independent Ethereum providers. Capture canonical L1 headers and transaction tries for 26367900–26367973. Reconstruct full receipt tries where the header bloom permits a relevant deposit or system configuration event; retain unrelated logs in those tries to preserve global log indices. Check every header and reconstructed trie against its published hash/root.
2. Capture OP block headers 159257551–159257842 and transaction index zero proof paths for the reset history. Supply full authenticated bodies for the preceding 40 blocks so Kona can check span-batch overlaps. Check the L2 parent chain and derive the safe and next output root preimages from the canonical headers and account proofs for the L2-to-L1 message passer at `0x4200000000000000000000000000000000000016`. Verify the account proofs against the L2 state roots and check the storage roots against the post-Isthmus withdrawal roots in the headers.
3. Use a prestate trace of OP block 159257842 to locate account and storage accesses, then retrieve trie preimages and contract code from the preceding state root. Include the EIP-2935 and EIP-4788 system contract proofs and code separately. One storage deletion collapses a trie branch: the needed old sibling `cddddc2493cc827add73f8933a3bb869e4841ea0b82c4cb77e3bf0a476006e70` was recovered from the poststate account/storage proof by reconstructing its old hex-prefix suffix and requiring an exact Keccak match.
4. Retrieve the inbox blob bodies and commitments from beacon sidecars at the corresponding Ethereum slots. Check each commitment against the L1 versioned hash, then generate and independently verify a standard EIP-4844 blob proof using [c-kzg 2.1.8](https://github.com/ethereum/c-kzg-4844/tree/v2.1.8) and its Ethereum trusted setup (`trusted_setup.txt` SHA-256 `d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7`). Do not assume the legacy beacon endpoint's proof field represents this EIP-4844 proof under PeerDAS. This capture contains 90 sidecars, of which Kona requested 85. The guest batch-verifies the supplied set before returning any blob to derivation.

The capture used archive RPC responses as witness material. Acceptance relies on hash, trie, KZG, and execution checks in the verifier. For this fixture, changing the anchor hash, next output root, a consumed blob byte, or swapping in a different valid KZG proof all caused native rejection with no public result.
