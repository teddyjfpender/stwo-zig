# Capacity attempts (not qualified block proofs)

All workloads use the same pinned Ethereum block fixture. These failures are
retained alongside the successful segmented measurements; none contributes to
qualified proof throughput.

- `monolithic-as8.json`: main-program trace failed under an 8 GiB virtual-address
  limit (native vector allocation failure during software Keccak finalization).
- `monolithic-oom.json`: uncapped main-program trace was killed by SIGKILL;
  cgroup `memory.events` advanced from zero to one OOM kill. The container limit
  was 8,589,934,592 bytes. RSS and timing are the recorded Linux `wait4` values.
- `two-transactions-proof-results.json`: the first two-transaction body chunk
  reached Zig proving but exited with `OutOfMemory` under the 8 GiB address-space
  guard. Its init proof succeeded; this remains a failed, incomplete bundle.

An experimental external RSS sampler used during the uncapped attempt could
not resolve child PIDs across namespaces. Its sampled peak is invalid and is
excluded here. No sampled RSS value is used to qualify a measurement.

The single-transaction run was interrupted during the 25th transaction trace
export when temporary files exhausted the 32 GiB filesystem. The retained 25
proofs (init plus 24 transaction chunks) were all independently reverified
before resumption. Their ordered transaction commitments also matched. Large
intermediates now use a temporary directory outside the retained evidence tree.
The final summary reports session count and does not call this an uninterrupted
end-to-end sample.

Readable `.log` copies have ANSI colors and trailing blanks removed; JSON
measurements are unchanged. Original retry logs remain in the proof archive.
