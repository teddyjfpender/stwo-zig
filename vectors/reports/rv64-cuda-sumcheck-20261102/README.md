# Resident sumcheck feedback and numerical proof admission

Continuation of PR311 at `93bfb2fdb3fa5bc43dd96aed685b598cb5d1bd28`.
This closes one LogUp oracle's sumcheck loop on-device; it is not a full GKR
batch, an Ethereum proof, a physical PCS binding or a security promotion.

## New behavior

- Native cubic correction, canonical trimmed coefficient absorption, ordinary
  Blake2s/raw-mod-OM31 challenge sampling, claim/Eq updates, folds and terminal
  mask packing all use resident buffers. The host schedules geometry only.
- The typed controller preflights every owner/generation/capacity and disjoint
  reservation before the first mutation. Two fold banks, one immutable Eq table
  and bounded proof records are reused across all rounds; no allocator, host
  field transfer or synchronization enters the numerical loop.
- Only32 terminal-mask words,40 state words and44 words per round need readback.
  Compact assembly uses the existing native sumcheck verifier and LogUp gate,
  and checks every recorded challenge, channel digest/draw count, claim and
  terminal relation. Physical source/PCS binding is still mandatory.
- Interpolation clears the rational root denominator and batch-inverts two
  factors in one norm descent: **one secure inverse instead of three**, with
  the exact original pole gates retained.
- An opt-in split secure-sum grid exposes twice as many first-stage blocks,
  with **80 versus128 registers/thread on sm120** and128 versus256 shared bytes.
  It rereads first-half data; combined remains the default until measured.
- Failed device rounds zero their records/challenges and invalidate ordinals;
  already queued folds therefore read defined neutral values, while sticky
  failure blocks admission. This requires device sanitizer validation too.

## Evidence

| Gate | Result |
|---|---|
| Focused ReleaseSafe tests | 20/20 pass |
| Focused ReleaseFast tests | 20/20 pass |
| Real native-context/C-ABI object type-check | Both modes pass |
| Full native proof/transcript/mask comparisons | 10 cases,38 round records |
| Random cubic comparisons with native interpolation | 1,024 pass |
| Native OM31 inverse comparisons | 512 pass |
| Independent Python polynomial-tower oracle | 4,196 pass |
| Malformed framing/fields, tampering, pole/order rejection | Pass |
| Proof assembly allocation-failure cleanup sweep | Pass |
| Focused package contracts | Pass |
| Source-conformance unit suite | 31/31 pass |
| CUDA sm89/sm120 GKR and round kernels | Compile; no reported spills |
| Both real-context fat-binary harnesses | Compile/link |
| Hardware execution | **Exit77: no NVIDIA device/driver attached** |

`validation.json` binds exact source hashes and records every unperformed gate
as false. Logs distinguish compiler properties from hardware observations.
The round-control kernel has compiler local stack storage (192 bytes on sm89,
64 on sm120) and high register usage; no claim of stack-free execution or
measured occupancy is made. Profile this control stage and the split/combined
tradeoff before selecting device-specific policies.

The host numerical bridge executes the same field/round arithmetic header,
then compares to the native prover and independently verifies compact records
with the native verifier. This is not a substitute for executing kernels on a
GPU, the pinned Rust protocol oracle or a fresh complete-block receiver.

## Remaining work

Connect actual RV64 metadata/witness producers and physical binding, batch the
mixed-instance GKR protocol around this capability, complete OM31 PCS/DEEP/FRI,
and qualify full-block output on2/4x4090 and2/4x5090. Run memcheck/initcheck,
racecheck/synccheck and Nsight before claiming utilization or latency gains.
The existing full-v3, recursion and security-certification gates remain closed.

Broad fast CI still stops on the same six inherited formatting failures;
source-layout checks report no finding naming a touched file. Local hook
feedback may be bypassed only with disclosure, as allowed by CONTRIBUTING;
no hosted CI or production proof-admission bypass is included. Read
`tests/cuda/rv64/README.md` for reproducible hardware commands and timing scope.
