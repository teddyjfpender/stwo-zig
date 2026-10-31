# Canonical public RAM tuples replace redundant boundary range queries

The scalable Word16 INIT and TEARDOWN components now use MAIN23/INTER20
and47 degree-at-most-three residuals on native2n. The full public RAM14 tuple
has independently typed address/value u64, epoch u16, tick u24 and rights u2.
The statement and its digest enter Fiat–Shamir before MAIN roots and lookup
challenges. Each accepting receiver compares each physical boundary RAM claim
with expectedClaim over its validated public tuple list. This sampled multiset
binding supplies canonicality for those tuple coordinates. The usual lookup
soundness error remains; this is not deterministic equality from one field sum.

Only the four strict address-gap U16 queries remain. Boolean active/permissions,
known row count, inactive zeros, all sorted-address equations, Boolean carries,
no final overflow and nonzero gap inverse remain. With canonical tuple limbs,
each address-add equation has integer magnitude below M31. Four canonical gap
limbs have sum below262,144, so its strict inverse excludes an equal address.
The source retains the same typed public tuple metadata after MAIN retirement.
It counts4 U16 queries per physical row, including padding, and no U8 queries.
The U8 claim is forced zero in the AIR and in both closed/global claim guards.
The separate RAM prefix remains independently authenticated.

The new physical encoding has RAM inverse/prefix8, two strict gap-pair inverses8,
and one gap prefix4. It saves28 committed base columns and four previous-prefix
coordinates per boundary. The packet0 pair at log20 saves58,720,256 source cells
(224MiB raw) and117,440,512 native2n point values. This does not remove the
public RAM sidecar or change MAIN23. Global executions still place one INIT
at genesis and one TEARDOWN at the end, with inactive boundary sides at minimum
geometry; the per-packet savings are not added a second time to block savings.

The strongest gate deliberately constructs a complete valid CPU/RAM proof
with two balanced noncanonical boundary ghosts. One unused public word has
its private low limb increased65536, high limb decreased1 and address carry
adjusted. All local range, ownership, physical proof and global ledger checks
pass. Fresh bare polynomial verification accepts it. The accepting receiver
rejects each ghost's mismatch with its public RAM14 tuple claim. Replacing
both claims with public expected values preserves ledger closure but fails
transcript/proof verification. This demonstrates why global RAM closure alone
cannot replace each boundary's public authority.

All four accepting core/global/Keccak/shared-Keccak paths retain this explicit
anchor. The separate two-PCS boundary diagnostic also retains it; its logs,
offsets and schema now derive the new boundary encoding authority. It remains
a diagnostic, without CPU coverage authority. Legacy closed-RAM/load-store
fixed-public-selector components retain their exact equations and proof bytes.

Safe/Fast tests include all16 packed lanes against arbitrary scalar residuals,
dense-QM31 cubic checks, serial/1/4/16 interaction equality, OOM, strict poles,
partial worker submission drain, omitted-claim balance attacks and the actual
noncanonical full proof. A real4,194,303-instruction packet freshly verifies
with all708,957 RAM records and CPU public fields identical to its control.
See public-boundary-ranges-v2.json for hashes and qualified limits. Observed
timing overlapped engineering and is not a paired speedup or block benchmark.
