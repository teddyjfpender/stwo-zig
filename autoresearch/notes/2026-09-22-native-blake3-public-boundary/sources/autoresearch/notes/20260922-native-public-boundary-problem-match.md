# Native BLAKE3 public-boundary arithmetic

Task: reuse existing native public-sum arithmetic on a concrete verified BLAKE3
capture, without importing the older outer-roster source wrapper. Reuse the
canonical graph builder, typed input-source mapping and arithmetic graph mirror
through the public facade. Inputs: authenticated canonical public wire, four native
public sums/total, first four native relation pairs, canonical register/memory
bytes and selectors. Exact layout mapping, O(inputs + graph nodes) work/storage.
No new public-sum formula or cryptography. Canonical graph recomputes every public
term and checks published sums/total and snapshot identity limbs. Validate zero
outputs; changed public sum input must fail. Copy all inputs/bindings; ownership
must survive constructor return. This is graph qualification, not completed parent
input routing. Aggregate-claim total linkage, public-input encoding/byte constraints
and relation sharing must still be included in the joined parent.
