# Execution-wide Keccak truth: implementation contract

Status: qualified bounded three-proof prefix mechanism. Actual shared proofs,
fresh independent receivers and adversarial physical-proof gates pass. Existing
service-v1 remains unchanged; no legacy/default route activates this protocol.

The ordered inventory is N CPU+lane-bridge proofs followed by one Keccak-truth
proof. Every actual fixed/MAIN root is sealed before common RAM14 and IO11 draws.
CPU entries bind their complete existing public request, epoch, step coverage,
program/image identity, declared native geometries, service count and derived
first call ID. The truth entry binds the same execution context, total service
count and independent Keccak geometry. Its first call ID is1. The receiver
recomputes all CPU call-ID spans by prefix sums; they are disjoint and cover the
truth span. Captured native u64 call IDs grant no proof authority.

Each CPU proof contains the canonical Word16 roster (seventeen roles in the
fixture; sixteen when qualified empty DIV omission is explicitly selected) plus the existing
66-MAIN/116-INTER bridge. The 1923-MAIN/2596-INTER permutation and chi/xor tables
are absent from CPU proofs. The single truth proof contains those three unchanged
components. Actual CPU OWNER19 closes locally against the bridge; IO11 closes
against the execution-wide truth worker; RAM14 closes across CPU shards with one
pristine first INIT and one physical last TERM. CPU/register/PC continuity and
all budget/genesis checks remain unchanged. All physical claims enter their
own proof transcript before interaction commitment; omitted fields stay zero.

The CPU merged prefix prevents pretending each typed debt has an independent
physical claim. Receiver checks each CPU's local non-RAM/non-IO sum exactly,
then checks aggregate RAM separately and bridge IO plus the three truth claims
jointly. The latter is a rational-identity argument covering IO and the truth
proof's local chi/xor families. All STARKs and actual manifest roots are verified
before acceptance. No native ledger target or loose external alpha is accepted.

Shared positive IO mass is50*total_calls. Chi/xor masses are bounded for the ONE
truth component with existing admitRoster; at most111848 calls fit characteristic
admission. A larger execution needs an explicitly qualified multiple-truth
inventory, not a silent field-wrap exception. U16/U8 remain per-CPU local vectors
and include every padded bridge query. Global absolute RAM mass includes all
ordinary LS updates, all50-per-call bridge state terms and both boundaries.

The qualified three-proof fixture uses the existing SD→K / LDx0→K four-instruction
program and25 cross-page words. It rejects a physically valid forged epoch0
predecessor, false K output, missing/swapped truth roots, forged call-ID span,
wrong public count and balanced physical-claim changes. Existing service-v1
proof artifacts must remain unchanged by shared helpers.

Cost must distinguish reduced opening width from native work. Global K geometry
may improve or worsen power-of-two padding relative to the sum of local K
geometries; it is not automatically a native-cell saving. The main expected win
is removing the roughly11000 K OODS samples and thousands of native leaf values
from every CPU proof, paying them once at the truth proof's independent height.
Native prefix hashing already reuses lower-height prefixes; no all-columns-at-
CPU-height compression estimate is assumed. The extra truth proof has its own
FRI/PoW/checkpoint costs. Complete source/LDE/quotient/key/mask/proof-size and
receiver measurements are required before a performance claim.

The first harness is bounded and centrally retains worker PCS owners. A scalable
coordinator owns only specs/root receipts; worker coefficient storage still needs
an explicit process/spill/memory budget at the global barrier. This is not a full
Ethereum block, secp implementation, halt/output certificate or recursion proof.
Parameters remain q70/P26/blowup1 (nominal configuration96); whole-protocol bits
remain unestablished after rational-degree/mass and union accounting.

The one-truth fixture is a bounded first slice, not a requirement for one giant
execution tree. A production extension should admit ordered truth entries
`{first_id,count,log}` whose disjoint spans cover all CPU call IDs. Chi/xor masses
then apply separately per truth proof; IO mass stays execution-wide. For the
real32,835-call roster, one log19 provider and two log18 providers have the same
summed native permutation area, while two providers halve each worker's peak and
add one proof/mask/FRI/PoW roster. No claim is made that one option fits a32GB
device until complete phase/lifetime measurements are available.

## Bounded plural truth protocol

The additive `produceBounded` / `verifyBounded` entry points select a distinct
version-3 transcript. The original version-2 `produce` / `verify`, Bundle and
single-truth durable wire remain unchanged wrappers around the same lifecycle.
A receiver supplies ordered `Truth{setup, first_id, calls}` entries independently
of the proof. Every span must begin exactly at the prior span's end, beginning
at1 and ending at the sum of CPU calls plus1. Empty entries are rejected except
one empty entry for a zero-call execution. This is an exact cover, not a native
count assertion. First IDs also enter the permutation AIR instance parameters.

The complete manifest orders all CPU fixed/MAIN roots first and all truth
fixed/MAIN roots second. CPU public transcripts bind the truth roster length;
each truth transcript binds its ordinal, roster length, first ID and count.
Every worker remeasures its retained roots before deriving challenges. The
receiver recomputes this complete expected inventory before decoding proofs.
All truth and CPU proofs must verify. IO and RAM are drawn from the full
manifest; chi/xor are drawn independently at each truth ordinal. The common IO
positive mass is50 times total calls and must remain below the characteristic.
Each truth separately satisfies the existing chi/xor admission bound. Summing
local chi masses would wrongly couple independently challenged families.

The four-proof control splits the two same-buffer calls into two log5 truth
workers. This increases native padding and table/proof overhead versus the
single paired log5 worker; it is a correctness and bounded-ownership gate,
not a performance win. Larger bounded rosters trade a smaller per-worker peak
against extra fixed-key/header/mask/FRI/PoW costs. Actual per-worker coefficient
storage remains in the bounded central harness; arbitrary multiworker device
fit or coordinator memory scaling is not established by this fixture.
