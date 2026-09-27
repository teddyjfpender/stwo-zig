# Persistent workers in the bounded recursion DAG

CPU and Metal detached-parent producers now accept `--worker manifest.json sha256`.
The first manifest is an existing version-1 pinned batch containing exactly one
request. It fixes the session, PCS cache and retained scratch budgets. Subsequent
newline-delimited JSON messages on stdin carry `path` and `sha256` for another
pinned single-request manifest. EOF releases the workspace and runtime. Invalid
framing, pins, changed budgets or failed proof requests terminate the worker.

Each response follows request-local teardown. Metal additionally checks the
authenticated runtime identity, lifecycle counters, released call leases and
fresh device/Poseidon dispatch. The response remains an unverified candidate;
standalone verification and qualified artifact admission release DAG dependencies.
The producer stays alive during verification, unlike the older fresh-process
qualification route. Independent outputs cannot overwrite existing proof bundles.

`scripts/recursive_proof_worker_pool.py` supplies the producer transport for the
existing ready-DAG scheduler. Each slot owns one process and one request at a
time. Errors/timeouts kill and reap workers and active verifier process groups;
there are no automatic retries. Idle resident workers remain included in the
pool's memory reservation. All workers must shut down successfully before the
replay is marked successful.

## Evidence

Both producers built in ReleaseSafe. Fifteen focused Python tests pass (eight
existing scheduler tests and seven pool tests), covering reuse, admission barriers,
worker failure, blocked-reader cancellation, malformed responses, resident memory
admission and failed shutdown. The real Metal worker rejects changed budgets,
truncated follow-up framing and a bad manifest pin. Valid proofs emitted before
the first two errors still independently verify and match qualified artifacts.

Apple M5 Max / 64 GiB, unchanged developmental `recursive_q193_v1`: 193 queries,
16 PCS PoW bits, 10 interaction PoW bits, log blowup 1, fold step 4. This is not
the CSP 70-query profile or production-security qualification.

| Seven-parent replay, retained leaves | Wall seconds | Peak sampled sum of RSS |
| --- | ---: | ---: |
| Two persistent workers | 30.006678667 | 9,024,733,184 bytes |
| Two fresh-process slots, same binary | 30.735065875 | 8,888,614,912 bytes |

These are one observation per route, run sequentially with the same RSS monitoring,
not an alternating statistical comparison. No reliable speedup is claimed.
Timers include standalone verification and worker shutdown. Both routes independently
verify seven fresh proofs and preserve all input and qualified output hashes.
The persistent route builds one transform plan per worker, serves five requests
on one worker and two on the other, and records seven total PCS graph builds and
seven hits. The reservation is 8 GB per slot / 16 GB total; it is not an OS limit.
RSS is sampled about every 100 ms, misses between-sample peaks and device allocations,
excludes descendants, and can double-count shared pages. Monitoring adds overhead.

Two repeated CPU requests in one worker also independently verify, with one
transform plan, one PCS graph build and three hits. The diagnostic process took
17.903 seconds; there is no CPU speedup claim. Including rejection qualification,
this checkpoint has **18 fresh independently verified proofs**.

No builds or other proof benchmarks overlapped the timed replays. Source conformance
reports the same 103 pre-existing finding identities; `git diff --check` passes.
`evidence/` retains reports, logs, commands/manifests, verifier receipts, test/build
logs and qualification scripts. `sources/` snapshots the implementation.
`manifest.json` pins these files. Full proof bundles remain in the corresponding
`/tmp/stwo-recursion-worker-*20260921` directories.

## Replay

Use `autoresearch/benchmarks/recursion/tree_replay.py` with its existing admitted
receipt directory, producer binary/pin, new output directory and byte reservations.
Add `--persistent-workers` for the resident transport and optionally `--sample-rss`.
Omit the persistent flag for the same-binary fresh-process control. The driver holds
the build lock once around the whole replay, allowing bounded internal concurrency.

## Full objective remains active

| Requirement | Current state | Remaining work |
| --- | --- | --- |
| Persistent plans, buffers and bounded scheduling with overlap | Runtime/transform/PCS plan reuse integrated with concurrent DAG workers; sampled aggregate RSS | Useful final-layout buffer reuse, explicit preparation/proving pipeline, controlled whole-product qualification and representative large programs |
| Fused PCS/DEEP components beyond muladd/dot4 | Target identified by source comparison and row census | Implement, preserve all bindings, regenerate identities, soundness/parity checks and full-proof measurements |
| Direct witness generation into final layout | Earlier selected-lane emission retained | Remove remaining authority/materialization passes and integrate final-layout generation |
| Separately reviewed recursion parameter experiment | Frontier machinery and upstream tradeoffs inspected | Versioned experimental profiles, security comparison/review and fresh proofs |

Requests are sequential within a worker. Concurrent workers can overlap independent
work, but this checkpoint does not claim stage-level overlap measurements or an
in-process preparation pipeline. Scratch retention is still zero for the measured
profile. Small cache/pool gains do not substantiate the tenfold aspiration; reducing
the PCS/DEEP witness and repeated materialization is the next substantial target.
