# Lifted alias consistency without witness-dependent producer IDs

Task: enforce that every (trace column, projected row) has one M31 value,
while preprocessing depends only on verifier-owned column geometry/query count.
Current blake3_opening_inputs.Builder.trace chooses canonical wire IDs and read
multiplicities from a hash map keyed by actual projected positions. Removing that
sharing alone would lose consistency for different lifted tree positions.

Canonical match: sparse read-only memory consistency, sorted adjacency plus
multiset equality. Cairo's paper describes sorting with permutation checking
(https://eprint.iacr.org/2021/1063); web search exposed the relevant passage but
full PDF fetch was blocked, so no exact equation is attributed to it here.
Our equations below are derived; no external code is copied. Reuse the project's
existing typed recursion_wire multiset relation and byte-pair range provider.

Alternatives: pairwise equal-index comparisons cost O(q^2) per column; a dense
array costs O(domain size); current host dedup costs expected O(q) but changes
fixed identities. Chosen sparse sorting costs O(q log q) host work, O(q) rows and
storage per column. Fixture q=17, production recursion q=193; larger column
counts multiply these costs. No speedup prediction until integrated measurement.

Represent a full u32 projected index by two 16-bit limbs in lookup tuples, so
index p or greater cannot alias M31 zero. A sorted row consumes one input tuple
(table, lo, hi, value, 0, 0), consumes its preceding rank tuple and emits its own
rank tuple under a separate chain circuit. Four bounded-byte gap equations and
three boolean carries enforce previous_index + gap = current_index without u32
wrap. The bounded byte sum of gap is zero exactly when gap is zero; a field inverse
witness enforces that predicate. Equal adjacent indices require equal values;
the initial row is exempt from equality with the constrained zero sentinel.
The terminal rank has no downstream read. Rank/circuit/enable fields are fixed;
indices, values, gaps, equality status and inverse are private. Namespace separation
and external tuple authentication are required composition contracts.

Implement/qualify the sorted-row AIR and complete CPU multiset proof first, then
connect unsorted projected-index producers and remove capture-dependent sharing.
Do not remove existing consistency until the whole replacement is joined. Test
u32 endpoints, cross-byte carries, equal/inconsistent duplicates, descending rows,
zero padding, range aliases, fixed invariance, typed identity/export, permutation
multiplicity and wrong anchored values. The primitive alone does not qualify
parent keys. Integration must bind projected indices to authenticated query bits.
