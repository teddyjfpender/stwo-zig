# Joined Ethereum service CPU control

The v1 and v2 fixtures execute twelve real RV64 instructions with one Keccak
call, secp256k1 generator ADD followed by DOUBLE, full-width MUL, signed DIVW,
and RAM loads. All seventeen CPU/ROM/BYTE/DIV/MUL/Keccak/secp components share
one PCS transaction. Both crypto bridges use the same CPU state challenge and
the global BYTE provider. Main commitments precede those shared challenges.

Both packet formats pass ReleaseSafe proof generation and independent setup
reconstruction. The compact tape path (global clocks offset by 2^40) produces
identical proof bytes to the retirement journal. Each fixture passes 34 fresh
receiver cases, including policy/roster/count/ID/geometry mutations, full-width
program/PC and RAM boundary changes, each secp claim, previous CPU ADD/DOUBLE counters and service prefix openings, and balanced changes to a
CPU service claim and provider bridge claim.

- v1: 3,015,640 proof bytes, SHA256 `d2e890e174671e05af3e5b6abd47afb441eca6d1d0601c361cd385508fe9b99e`.
- v2: 3,017,800 proof bytes, SHA256 `e66d192450a35c8ea4eea969bfaca8abcb53a4596b55adf3b2132068dae143e4`.

These are public-cell boundary control fixtures, not a complete Ethereum block
proof or a private authenticated-RAM qualification. The rootless material and
concrete proving-source APIs allow the private-RAM coordinator to append its
physical tables and close their state effects against the register boundary.
Count and first-ID data remain public instance data; immutable setup depends on
program, profile/policy, provider roster, and domain geometry.
