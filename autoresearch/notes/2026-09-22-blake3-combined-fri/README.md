# One proof of FRI arithmetic and all BLAKE3 FRI paths

Previous turn: progress. Canonical FRI arithmetic had its own complete proof,
but its values were public, separate from the hash-group proof.

This stage joins them in ONE ten-component CPU STARK. A real BLAKE3 PCS capture
has 17 raw queries and two FRI layers with fold widths [16,2]. Every one of the
34 folding groups is authenticated through typed canonical encoding, packed
leaf hashes, shared subtree hashes and its upper path to the public layer root.
All 1,224 scalar authenticated-value coordinates are private main-column
producers shared by canonical FRI arithmetic and the packing/encoding path.
Their emission counts include arithmetic reads plus exactly one hash read.
The complete interaction ledger closes and core verification passes.

The existing signed wire component already separates its public-value
constraint enable from its emission weight. A new `privateCoordinates` helper
uses that existing behavior explicitly: fixed identities/multiplicities, private
main coordinates, zero expected-value anchors. These producers derive their
authentication from the joined hash and arithmetic consumers. No AIR or semantic
digest changed, and this is not a zero-knowledge claim.

Trusted fixed columns are rebuilt separately from graph/schedule/public inputs;
private FRI values and private digests are absent from those columns. The fixture
roster now generates its enum instead of extending a size-dependent ladder.
The arithmetic components, their proof-kind parameters and the hash protocol are
unchanged. Other FRI inputs (DEEP answers, challenges, raw query coordinates and
last-layer coefficients) remain explicit PUBLIC auxiliary inputs at this stage.

An independent exact recursion-wire tuple ledger checks every producer and
consumer across all ten components. Changing one private scalar emission while
leaving consumers unchanged yields nonzero tuple balances. The existing false
public-input preprocessing test also rejects the substituted statement.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

Final guarded result: all four steps succeeded; one test passed, approximately
5 seconds runtime and 764 MiB max RSS; compilation took 28 seconds on M5 Max.
Formatting and diff checks pass. See tests.log. Development parameters remain explicit:
inner fixture 17 queries/4-bit PoW; outer proof 8 queries, blowup1, zero PoW.
Runtime here is qualification cost, not a production performance comparison.

Remaining: constrain transcript-derived challenges/queries/commitments and PCS
DEEP/trace openings in the same proof, integrate production source admission,
assign new suite/key/artifact identities, qualify CPU/Metal and parent-of-parent.
The experimental test assembles the joined roster; production capture/proving
still uses Poseidon. No end-to-end speedup or stronger security is claimed.
The original goal and the BLAKE3 migration remain active and unfinished.
