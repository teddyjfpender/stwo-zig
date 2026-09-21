# Canonical producer modules, 2026-09-18

CPU and Metal parent commands now import the same dedicated
`stwo_riscv_detached_parent_producer` module instead of the broad CPU integration
facade. The five unused detached facade exports were removed. Key setup's build
module also no longer receives the broad integration binding.

The transitive integration-layer guard covers CPU/Metal leaf and parent commands
and CPU key setup: 24 source files, no historical temporal/test harness and no
broad integration import. Frontend/backend authorities are named external
interfaces in this guard and have separate checks. All 35 source tests passed.

Fresh CPU/Metal/AOT four-segment products passed 384 checks, including producer
exit, fresh verification and hostile replay. All 21 artifacts are identical to
the canonical baseline. Both products used the same frozen source snapshot;
protocol identities and pinned admissions did not change. This is development
profile evidence, not production-security qualification.

The adjacent frontend-contract-audit.md corrects the next-work distinction:
terminal V1 and resumable V2 already share execution and typed opcode geometry.
Their public-I/O contracts differ. Before treating every V1 name as an obsolete
untyped route, audit the native infrastructure equation owners and close actual
typed-definition gaps. The overall frontend authority audit and final useful
continuation qualification remain unfinished. Speed work remains deferred.
