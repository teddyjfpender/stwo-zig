# Scoped persistent parent admissions

Persistent fused setup workers previously retained a shallow copy of the last
 stage's `Bus.Values`. That owns statement words/felts and public claim slices.
 `Bus.Prepared.deinit` freed those arrays after publication, but the next warm
 acquisition called `Plan.validateRows` before rebinding; its first operation
 validated the stale admission. `Plan.tryRebindAdmission` also read the previous
 public values through that validation path. Empty-cache fixtures cannot expose
 this actual lifetime defect.

The repair keeps a single original producer and worker kernel. Existing
 `PlanForProtocol` and `WorkerForProtocol` retain their original admission field
 type and borrowing API. New explicit
 `PlanForProtocolScopedAdmission`/`WorkerForProtocolScopedAdmission` use an
 optional synchronous admission slot plus a separately owned, pointer-free
 template key. The setup constructor performs the unchanged admission, fixed
 commitment/root and exact row checks, then clears the scoped slot before
 returning. No fabricated empty public statement or accepted flag is installed.

The canonical generic setup cache selects the scoped worker. Its hit check
 calls `validateRowsForAdmission(rows, current_admission)`. Both default and
 scoped `tryRebindAdmission` authenticate the supplied current admission before
 comparing compatible fixed geometry and the original fixed metadata. They
 never validate a previous dynamic tuple. The original comparison still ignores
 only query count and PoW when testing fixed-template compatibility; exact logs
 and preprocessed root must match. Every original fixed digest, fixed row
 length, physical main column count, column log and column extent guard remains
 in one `blake3_parent_fixed_row_guard_v1` body.

The real cache lease carries the current independently validated admission.
 Its joined request performs acquire, optional required-ID check, preflight,
 and original `proveAdmittedConsuming`. The worker binds current values only for
 that synchronous operation. `Worker.Lease.deinit` releases the scoped slot
 before unlocking, including failed rebinding, rejected preflight and proof
 errors. A request without current binding fails with
 `ParentDynamicAdmissionNotBound`. Constructor success exports no initial
 borrow either. The cache retains only its owned key/schedule, fixed setup,
 bounded workspace and pool; prior dynamic values cannot be dereferenced by a
 later hit.

`artifact.Owned` contains independently allocated core proof data, fixed-array
 claims and the key ID, not admission values. The producer checks output/scratch
 nonaliasing and validates the artifact while the current admission is live.
 The worker retains the proof's budget. Removing the admission afterward does
 not affect the returned proof or the stage's separately owned public values
 used for encoding and mandatory fresh verification.

Other direct reusable producer wrappers were inspected. Execution/tree stream
 workers use the original key/expected-ID admission without public slices.
 RAM/source/requester/public parent wrappers borrow a public owner under their
 explicit owner-outlives-worker contract and supply current admission to every
 `proveAdmittedConsuming`; their rebinding now avoids prior-value reads as well.
 No unrelated default wrapper was switched to scoped mode. Direct default
 `prove` still requires its original admission source to remain alive; the
 scoped API deliberately requires an explicit request admission.

The original proof-running native stage cache regression is source-updated to
 assert that the actual worker slot is null after each joined request. Its
 original source proof comparisons, independently rederived key checks, fresh
 recursive receivers and current output-value comparisons remain. It was not
 executed by this author.

Pure fixtures exercise source teardown before rebinding, latest metadata
 selection, partial allocation cleanup, pointer-free retained key types and all
 original row/log/column/extent/content guard faults. Metadata probes never
 construct a Plan/Worker/Verified/capture or nominate an expected key. The
 isolated root retains real default/scoped producer, worker and cache bodies
 without importing CPU Session/Driver markers; the combined root also retains
 the actual five-family publication/pipeline bodies. Root owns subsequent
 semantic, Debug and body qualification. No compiler, test, PCS, proof, segment,
 device or benchmark was run by this source author.
