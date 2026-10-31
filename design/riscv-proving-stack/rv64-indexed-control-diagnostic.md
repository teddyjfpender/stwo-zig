# Indexed control diagnostic

This experimental register-only proof replaces the qualified ALU/binary CPU's
four u16 PC limbs and four next-PC limbs with two immutable address IDs. It is
not selected by Ethereum or the default CPU profile. The direct witness has
40 main columns, 56 interaction columns and 49 CPU constraints, compared with
46/56/61 in the raw-address ALU/binary diagnostic. These are CPU counts, not a
whole-proof memory or speed result.

The expected raw program independently determines a sorted dictionary of full
u64 instruction addresses, static fallthrough addresses and aligned static
branch/jump targets. Each ID names one address, not a branch-expanded ROM row.
The fixed execution projection authenticates ID, next ID, decoded register and
function metadata, immediate and branch predicate. A second projection of the
same fixed rows authenticates ID and all four u16 address limbs. Its separate
multiplicity and prefix add one main and eight interaction columns to ROM.
The fused ROM has 23 fixed, two main and 16 interaction columns. Its padding
repeats the first genuine ID/address pair while disabling execution admission.
Invalid and unsupported words remain in the raw-program identity and address
map but cannot satisfy an active execution query.

Public u64 endpoints map independently through the expected dictionary. Active
and inactive rows retain unmasked ID adjacency, with first and final IDs bound
to the public endpoints. Static u64 wrapping occurs when deriving immutable
edges, never by incrementing an ID. A finite prefix may end at a static mapped,
nonfetchable address; this does not prove a successful guest halt. Unknown
dynamic exits are unsupported. No request-specific sentinel or fixed row is
introduced. JALR, RAM, services, full ISA coverage and Ethereum acceptance are
outside this diagnostic.

The same factored register, range and FUNCTION equations serve both raw and
indexed CPU paths. Canonical read values follow only when physical REG, ROM
and FUNCTION claims close, endpoints are canonical and local clocks are strictly
bounded. An open CPU component alone does not establish this lemma. No
46-column source matrix is constructed before the 40-column source.

Fixed columns are committed once per immutable geometry and leased into fresh
request transcripts. Component rosters, offsets and polynomial shapes follow
one concrete role list. Domain preparation uses the existing bounded WorkPool
column transform; row evaluation uses the same scalar or SIMD16 polynomial
authority and joined disjoint output ranges. Backend selection is not transcript
metadata. No third runtime profile enum was added.
