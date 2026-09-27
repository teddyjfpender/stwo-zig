# Recursion architecture and concurrency investigation

2026-09-21, Apple M5 Max, 64 GiB. This is local advisory research, not a judged
autoresearch result or an upstream benchmark comparison.

Read the [architecture comparison and implementation priorities](../../../design/riscv-proving-stack/recursion-architecture-comparison.md).
[sources.json](sources.json) pins inspected upstream repository heads and the
local base commit. Local preparation optimizations remain uncommitted; the
exact measured producer binary is pinned in [summary.json](evidence/summary.json)
and comes from the [previous qualified batch](../2026-09-21-recursion-preparation/README.md).

## Concurrent sibling diagnostic

The [script](parallel_probe.py) replays the admitted level-2 sibling nodes from
the retained eight-segment Metal tree. Six pair runs use serial/concurrent order
S,P,P,S,S,P, without a warmup. A pair timer covers production and process exit;
fresh standalone verification occurs after both processes finish, outside that
timer. STWO environment overrides are scrubbed except the profiling flag. The
qualification gate and its build lock were not modified.

- Serial pair seconds: 10.643224833, 10.822652542, 10.860988833.
- Concurrent pair seconds: 34.271782750, 6.384349583, 6.516081083.
- Medians: 10.822652542 versus 6.516081083 seconds, ratio 1.6609x.
- All 12 proofs verified independently and matched the admitted key, claim and
  proof hashes. Positive GPU dispatches and zero CPU fallbacks are recorded in logs.
- The first concurrent pair's delay is retained. The slower process reports
  5.264 seconds internally but 34.23 seconds externally. Its cause was not
  established. This diagnostic demonstrates concurrent proof correctness; it
  does not establish a reliable throughput improvement or production readiness.
- Per-process RSS is recorded by `/usr/bin/time -l`. Peak simultaneous aggregate
  memory was not sampled. No compiler or other benchmark was launched alongside
  these runs; ordinary host activity was not controlled.

[samples.json](evidence/samples.json) retains producer and verifier commands,
individual timings and qualified artifact hashes. `evidence/*.log` are raw
producer/resource logs; `*.verified.json` are fresh verifier receipts. Full proof
bundles remain under `/tmp/stwo-recursion-peer-research-20260921/parallel-probe`.
The script deliberately fails if that directory already exists; use a fresh
output path for another diagnostic. Its retained input paths depend on this host.

No upstream prover was compiled or benchmarked. StarkWare's repository checkout
warned about case-colliding `.codex/AGENTS.md` and `.codex/agents.md`; inspected Rust
source paths are unaffected. Proofman and ZisK heads are separately pinned and
are not asserted to be one resolved dependency graph. zkDTVM's current public
verifier, its older design article and its unavailable complete prover must not
be treated as one inspected implementation.

`sha256-manifest.json` records every file in this evidence directory except
itself. The comparison report is also pinned there. No proving implementation
or security parameter was changed during this investigation.
