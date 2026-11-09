# Opt-in pure-P2 truth-local GKR

This directory replaces the **local** Keccak chi/xor and classic secp byte
interaction traces with a source-bound LogUp-GKR child. The original truth MAIN
and global KIO/Wire LogUp arguments remain unchanged. This is a separate,
explicitly requested fragment authority; the production catalog, inventory,
root receiver and CLI do not select it.

`authority.zig` derives geometry and cost from the original receiver-owned truth
shape. `source_inputs.zig` streams at most 512 raw facts per request directly from
validated durable metadata, including partial intervals of 1920-query rows.
`native.zig` binds statement, full 36-byte FIXED/MAIN/manifest roots, ordinal and
all three exact instance/policy descriptions before drawing lookup challenges.
It verifies all denominator poles and whole-local closure. A checked child
remains pending physical source binding.

`witness.zig`, `projection.zig` and `component.zig` close each terminal marginal
through Eq and a cyclic prefix. They reuse the original tuple emitters, MAIN
arithmetic and global rational equations. The packed 16-lane M31 composition
kernel is shared with the classic route; only ten succinct public Eq auxiliaries
are added. The component has 16 local binding columns plus its unchanged global
columns. It retains Keccak's degree 5 / 4n domain; this work does not claim a 2n
Keccak rewrite.

`worker.zig` constructs MAIN once, transfers it to the PCS, retains only durable
metadata, generates owned INTER, and releases source metadata before native
proving. Whole-worker and child numerical allocator limits are mandatory.
FIXED setup is independently reconstructible and remains outside the worker
allocator, as do caller-owned input advice and returned serialized bytes. The
coordinator must budget those owners separately. Its identity differs from the
classic route even though FIXED bytes are identical. The manifest seals MAIN
before the local child starts; the child's full receipt and original global
claims enter the physical transcript.

`child.zig` uses the same typed payload and receipt authority inside the circuit.
`statement.zig` binds that child, the physical PCS/OODS/DEEP computation, global
claims, span and full public frame. Lane weights use a shared-product binary
expansion, requiring O(lanes) operations rather than O(lanes log lanes).

## Gates

Focused tests cover bounded query spans and padding, native child/manifest/
receipt mutations, exact native/circuit transcript parity, actual Keccak and
secp physical fragments, fresh independently reconstructed FIXED receivers,
canonical durable framing, allocator failures, and rejection of old authorities.
The pre-extraction classic Keccak/secp proof envelopes are pinned byte-for-byte
in `legacy_parity_test.zig`; both old fresh receivers accept those proofs.

Complete recursive numerical and adversarial gates pass for Keccak and secp.
Physical recursive qualification is separate. Whole-execution admission,
source-only recursive topology/factory integration,
complete-block qualification and controlled performance measurements remain
separate gates. A smaller native trace does not itself establish a faster
complete proof: local GKR facts, recursive verifier arithmetic, padding and
retention must be included in that measurement. The numerical resource cap
must be chosen from the actual instance sizes, not from a tiny fixture.

Security remains a 128-bit target under documented assumptions;
`security_qualified=false`. There is no certified whole-protocol claim here.

An explicit `initWithGkrOptions(..., .{ .coefficient_encoding = .fixed4 })`
policy retains four coefficients **before** each sumcheck transcript mix.
Trailing zeros are preserved through the wire and constrained verifier. This
can make an honest service leaf's coefficient-vector topology depend only on
source geometry; it does not pad a completed proof. Default construction keeps
the existing trimmed encoding. A future source-only root factory must select
and enforce its expected shape policy independently.
