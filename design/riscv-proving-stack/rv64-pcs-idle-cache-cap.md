# Optional upper PCS idle-cache cap

This isolated candidate introduces native environment setting
`STWO_RV64_PCS_IDLE_CACHE_BYTES`. Unset preserves the existing behavior and logs.
An explicit canonical decimal value caps unused upper PCS block bytes;0 means
no idle upper blocks. Empty/malformed/overflowing values and values exceeding
the unchanged admitted device cap refuse before CUDA context allocation.

The existing runtime already uses cudaMallocFromPoolAsync with a retained pool.
ResidentOwner separately retains unused PCS block allocations. New leases can
use the runtime pool but cannot borrow those still-owned upper-cache blocks.
The retained largest26235159 log records89 physical OOM recoveries across149
outer nodes (92including native stages). Its first outer recovery requested
3,489,660,928 bytes while upper idle blocks held13,038,146,168 bytes, active
blocks0, leases12,267,415,232 and physical free5,963,776. The compact receipt pins
the original complete log and the exact first event; these are old runtime
measurements, not results for this candidate.

After the existing joined retirePlanes/reset transition, the candidate returns
largest unused upper blocks to the SAME existing runtime async pool until
remaining upper idle bytes meet the optional cap. Equal-size ties follow
original vector order. It never selects active blocks, leases or domain planes.
Every successful context free immediately updates retained-byte/block ledgers;
a failing free preserves that descriptor and all remaining ownership, then the
existing exception path poisons the session. No fallible allocation or throwing
metadata move follows a successful free. Terminal context teardown retains its
existing joined cleanup authority. The default path neither scans nor frees
additional blocks and emits no new trim log.

Returning allocations to an async pool does not imply physical backing is
released. There is no cudaMemPoolTrimTo, release-threshold change, cap increase,
protocol change or public ABI addition. The intended benefit is cross-role
reuse, with no measured speed, RSS, GPU peak or recovery-count improvement yet.

The shared C++ policy is used by both the native owner and host phase emulation.
Tests cover strict parsing before an emulated context create, deterministic
largest-first/ties, unchanged active/lease/domain ownership, partial successful
free followed by terminal failure, malformed ledgers, and1024mask/cap cases.
They are CPU source checks, not native CUDA compilation or GPU qualification.
A standalone `test-pcs-idle-cache` build target runs the same checks. Future
qualification must preserve original default and optional-cap proof bytes,
fresh CPU acceptance, exact lease accounting and the largest28GiB shape before
any controlled quiet measurement. No GPU instance was started for this work.
