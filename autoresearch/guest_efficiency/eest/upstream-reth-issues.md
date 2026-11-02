# Two consensus bugs in the Rust guest's dependencies (not filed)

Found by the EEST run (`tests@v21.0.2`, receipt
`vectors/reports/rv64-ethereum-20261101/eest-guests-v1.json`). Both are in the
block executor the Rust guest links, not in our code: `stateless-validator-reth`
at `paradigmxyz/stateless@a134a621`, which pins reth `3d270d93` and alloy-evm
`065a125c` (`alloy-rs/evm`, crate 0.38.0). Both are still present on alloy-evm
`main` as fetched on 2026-11-01 (same lines). The Rust guest is unchanged here;
these are written up for an upstream report, nothing has been filed.

Check on reth/alloy-evm `main` and against the current EIPs before filing; the
code references below are to the pinned revision.

## 1. Empty EIP-7002 / EIP-7251 predeploy accepted (`SYSTEM_CONTRACT_EMPTY`)

**Spec.** EIP-7002 and EIP-7251 (block processing, system call): if there is no
code at the predeploy address (`0x00000961Ef480Eb55e80D19ad83579A64c007002`,
`0x0000BBdDc7CE488642fb579F8B00f3a590007251`), the block is invalid. EEST
expects `BlockException.SYSTEM_CONTRACT_EMPTY`.

**Observed.** reth executes the system call against an account without code;
the call succeeds with empty output, which is read as "no requests", and the
block is accepted. The Rust guest (host build and RV64 ELF), upstream
`stateless-validator-reth` (the generator's reference run) and reth's own
stateful replay all accept. evmone (our other guest) rejects with
"withdrawal system contract empty".

**Where.** `alloy-evm` `crates/evm/src/block/system_calls/eip7002.rs`,
`transact_withdrawal_requests_contract_call` (and the `eip7251.rs`
counterpart): `evm.transact_system_call(SYSTEM_ADDRESS, PREDEPLOY, ..)` with no
code check before or after; `post_commit` only rejects `Revert`/`Halt`.

**Cases (4 blocks, all invalid, all accepted).**

| fixture (under `blockchain_tests/`) | test id suffix |
|---|---|
| `for_cancuntopragueattime15k/prague/eip7002_el_triggerable_withdrawals/contract_deployment/system_contract_deployment.json` | `deploy_after_fork-nonzero_balance`, `deploy_after_fork-zero_balance` |
| `for_cancuntopragueattime15k/prague/eip7251_consolidations/contract_deployment/system_contract_deployment.json` | `deploy_after_fork-nonzero_balance`, `deploy_after_fork-zero_balance` |

Block 1 of each test (the first Prague block, timestamp 15k) runs while the
predeploy has no code yet.

**Impact.** Spec soundness gap: an invalid block is accepted. Not reachable on
mainnet today (both predeploys have code since before Prague), but any network
or devnet launching Prague without the predeploys would accept blocks other
clients reject.

**Suggested fix.** Before the system call, load the predeploy account; if its
code is empty, fail with a `BlockValidationError` (as for a reverted call).

## 2. Withdrawals credited after the request system calls

**Spec.** Prague block processing (EELS `prague/fork.py` `apply_body`):
transactions, then `process_withdrawals`, then the general-purpose request
system calls (EIP-7002, EIP-7251). A system contract therefore sees balances
that include this block's withdrawals.

**Observed.** In alloy-evm `EthBlockExecutor::finish`
(`crates/evm/src/eth/block.rs`, lines ~283-335 at `065a125c`), the request
system calls run first (`system_caller.append_post_execution_changes`, line
~299) and the withdrawal balance increments are applied after
(`post_block_balance_increments` + `increment_balances`, lines ~305-334). A
request contract that reads its own or another withdrawal recipient's balance
sees the pre-withdrawal value.

**Cases (8 valid blocks, all rejected).**
`for_{prague,osaka}/prague/eip7685_general_purpose_el_requests/multi_type_requests/withdrawals_credited_before_request_system_call.json`,
all four cases each (`request_class_{WithdrawalRequest,ConsolidationRequest}` x
`forward_{all,half}`). The test replaces the request predeploy's code with
`SELFBALANCE`-based code that forwards (all or half of) its balance to
`0xf36afef4dcb45e52f80cb039335952f77cec8960`, and credits the predeploy with a
1 gwei withdrawal in the same block. Expected post-state: the recipient holds
`0x3b9aca01` wei (1 + 1 gwei forwarded). reth forwards nothing (balance 0 at
the time of the call), so its state root differs: reth's stateful replay
reports "state root mismatch", and every `stateless-validator-reth` build
(upstream, crates.io host validator, our lean-profile host and RV64 guest)
returns `successful_validation = false`. evmone reproduces the fixture's block
hash, state root and request root exactly.

**Impact.** Consensus split, reachable in principle on mainnet: a withdrawal to
an address whose balance the request system calls observe. Whether the
deployed mainnet predeploys can observe it (they would have to read a balance
that a same-block withdrawal changes) is not checked here; the ordering is
wrong for any system contract that reads balances.

**Suggested fix.** Apply the withdrawal (and other post-block) balance
increments before `append_post_execution_changes`.

## Reproduction

With the runner in this directory (pinned fixtures, pinned stateless workspace):

```sh
E=autoresearch/guest_efficiency/eest/eest.py
C=/path/to/cache; W=/path/to/work
python3 -I $E fetch   --cache $C
python3 -I $E build   --cache $C
# 1. SYSTEM_CONTRACT_EMPTY
python3 -I $E convert --cache $C --work $W --filter contract_deployment/system_contract_deployment
# 2. withdrawals credited before the request system call
python3 -I $E convert --cache $C --work $W --filter withdrawals_credited_before_request_system_call
python3 -I $E host    --cache $C --work $W --filter system_contract_deployment
python3 -I $E host    --cache $C --work $W --filter withdrawals_credited_before_request_system_call
python3 -I $E receipt --cache $C --work $W --out /tmp/r.json
```

- `W/gen/*.jsonl` holds, per block, the generator's verdict (`reth`:
  "rejected: state root mismatch" for case 2), and `reference_output`, the
  upstream `stateless-validator-reth` result: byte 33 is `successful_validation`
  (`01` accepted, `00` rejected). Case 1 blocks are `negative: true` with
  reference byte `01` (accepted); case 2 blocks are valid with reference byte
  `00` (rejected).
- `C/target-rust-host/release/stwo-eest-rust-host INPUT.ssz` prints the Rust
  guest's verdict on one input (`REJECT` for case 2, a 43-byte output for
  case 1).
- The generator (`witness_gen/`) replays each fixture the way reth's
  `ef-tests` crate does, so running these fixtures through reth's own
  `ef-tests` at `3d270d93` is the natural upstream reproduction (not run here).
