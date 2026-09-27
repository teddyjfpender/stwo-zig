# Compact typed BLAKE3 G

Task: reduce the 704-column bit oracle to a byte-limb typed component with exact
existing universal lookup schemas. Shared canonical G schedule remains unchanged.

Canonical transfer: base-256 ripple-carry addition; XOR through the existing
65536-pair byte table; byte permutations for rotations 8/16; bounded low/high
splits for rotations 12/7. Compare with existing native Blake round evaluator's
16-bit arithmetic and split-XOR method, previously inspected and source pinned
in the migration notes. Byte representation fits the canonical RISC-V schemas
without a new relation registry or an untyped compatibility implementation.

Inputs: six u32 words, each four bytes. All input and addition-result bytes are
range requested. Every XOR byte is bound to the existing bitwise relation with
operation 2. Rotation-12 pieces use range_check_8_8_4 with zero byte slots;
rotation-7 low pieces use range_check_m31 with a zero byte slot and high bits
are Boolean constrained. Every assembled output is a range-requested byte.

Exact bounds: an addition byte sum is <=511, carry in/out are bits, so the
integer equality cannot alias modulo M31. A split/rotation equation is similarly
bounded below M31 once its lookup requests are discharged. Treating declared
byte types as automatic range constraints is explicitly rejected.

Derived geometry: 112 witness columns, 68 degree-two equations, 56 lookup
requests per G versus 704 columns and 1024 equations in the bit reference.
This is not a total proof speed estimate: interaction columns, table costs,
call relations, degree/domain padding and device cost still matter.

Validation: typed degree/schema checks; packed results equal native and bit
oracle; all witness-coordinate mutations; noncanonical/out-of-range values;
lookup membership against the existing byte/range semantics; a mutation that
passes algebraic roots but fails lookup membership. No production selection
until real lookup closure and call/control binding are integrated.

Revision before finalizing: using range_check_8_8_4 implies a 2^20-row generic
provider, and range_check_m31 another provider absent from the current detached
parent roster. Replace both with the already required byte-pair table: request
(value, value*2^(8-bits)) and constrain the multiplication, with both values
byte-bounded by that request. Input <=255 makes the equation integer-injective
below M31; the scaled byte bound forces the narrower range. This adds 12 witness
columns/equations but avoids extra provider families. Final geometry is 124
columns, 80 constraints, 56 requests, using only byte-pair and XOR schemas.
