# Explicit ready-lane resident-batch recursion candidate

The default combined-batch route stays serial and rejects more than one GPU.
The existing ready DAG is selected only by an authored producer manifest with
`recursion_mode: "ready_candidate"`, including a one-GPU qualification run.
The manifest also supplies a positive `recursion_worker_budget` (at most32)
and `recursion_max_pending_authorities` (default17, at most256). The existing
physical GPU IDs and byte caps remain explicit; duplicate IDs, more than4 lanes,
insufficient workers, unbounded pending slots and caps above28GiB are refused.
Each request's native worker count must cover the chosen total lane budget.
The driver never rewrites request settings or silently selects another mode.

The batch owns one original outer factory and one stable WorkPool per physical
GPU. Pools divide the one total worker budget, not one full budget per device.
For8 workers, one/two/four devices receive8,4+4,2+2+2+2 workers respectively.
Each factory uses that physical device's existing native context, trace committer
and composition backend. The default CPU-assignment fallback is unavailable:
all factories must expose original trace-only graph generation.

The native phase and its fresh verification finish before the live independently
derived keys, fixed authority and in-memory bundle enter runWithFactories.
No reload or alternate tree builder is introduced. Existing deterministic binary
carry IDs, right finalization, ordered coverage, durable publication, fresh parent
verification and failure draining remain the scheduler's authority.

Recursion graphs, proofs, lane owners and pool bookkeeping share the original
synchronized host budget through its verified recycler adapter. Existing
persistent native-backend setup caches retain their established ownership; this
route creates no additional transform or expansion cache. Lane helper stacks are reserved before pools spawn and
remain charged across the native phase and all batch requests. The idle native
pool's helper stacks are separately charged during a ready request; they had no
existing reservation to reuse. The scheduler borrows the lane reservation and
reserves only its active8MiB coordinator stacks, avoiding double charging. Native
pool work is drained at handoff. Every lane's ScopedPoolBinding selects its own
pool. Teardown joins helper pools before releasing outer factory metadata.

The existing beginBlock/endBlock loop still covers every physical device, and
each endBlock requires zero request leases. Operational reports record actual
serial/ready mode, physical IDs, lane worker counts, native/lane/coordinator
reserved stacks and exact original manifest SHA256. Candidate output also keeps
a durable byte-identical resident-ready-manifest.json. External production plan
pins must bind this authored manifest and the rebuilt producer asset; the mode
is not proof transcript data and is not inferred from device count.

This is source-qualified, default-off wiring. It claims no acceleration or
hardware parallel qualification. Before enabling it for measured delivery, a
one-lane run must reproduce every native and recursive proof byte, root and tree
ordering and pass the independent CPU receiver. Two/four devices then require
physical hardware, memory-fit, failure and independent-receiver qualification.
Existing native/combined serial runs and the queued GPU FIXED precommit candidate
are separate controls and are not silently combined with this experiment.

The first physical one-lane gate is now independently accepted: block26235156,
4CPU+7truth native workers,11 fresh outer leaves+10 fresh folds, no restored
proofs. Every13 native .bin file, bundle,22 outer proofs including root and the
ordered tree are byte-identical to the original accepted serial control. A
fresh ARM CPU receiver under independently rebuilt authority accepted native
and root together, with artifacts unchanged. Original mode/manifest/stacks were
checked by the strict candidate harness. The actual lane has8 workers; the
unchanged native request has16, hence15MiB reserved native helper stacks,
7MiB lane helpers and8MiB coordinator stack. The request took173.149s; the old
serial control took152.918s under different source/runtime/worker allocation.
This establishes the production API/custody/parity path, no acceleration or
2/4-device result. Serial remains the default. Receipt ready-n1-qualified-v1.json
pins the producer, runtime, original plan and independent receiver result.
