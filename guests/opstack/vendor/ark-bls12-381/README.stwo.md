# Local BLS12-381 scalar adapter

Copied from published `ark-bls12-381` 0.6.0, crate checksum
`be2ede2c0c96fa37d5d3484e8a59fec566c4a52b8c84bf993eaa6c67d7225a4c`,
upstream algebra revision `bffa52711f225e888c1a91e1ec9fc59f2d9d5c94`.
Original MIT/Apache licenses, source and Cargo metadata are retained.

Default `FrConfig` remains upstream Montgomery. The explicit
`stwo-canonical-fr-service` feature replaces only Fr255 storage with canonical
limbs. R=R2=1; generator and both subgroup roots are canonical; strict bigint
conversion rejects >=p; inverse starts at coefficient1; all products remain in
[0,p). Native products use an independent software Montgomery reference. Only
RV64 uses the already admitted arith256_mod tag0x30021, with a,b,c=0,m and four
output words in a160-byte initialized inline packet. The BLS Fq381 backend and
its existing Montgomery service remain unchanged.

This is a guest representation adapter, not a new AIR or cryptographic protocol.
The corresponding program image must select matching canonical blob roots;
selection derives from the actual FrConfig, including Cargo feature unification.
Root tests independently compare field/root/serialization/group behavior. No
feature is enabled by default, and existing selected guest binaries are retained.
