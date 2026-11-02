# Global shared RAM draw

Closed/genesis Word16 proofs still use `Core.draw` with exactly the historical
channel sequence. The complete-manifest global protocols use the named
`Core.drawWithSharedRam` entry point. Both call one private core draw authority;
there is no second list of component challenge draws.

The global authority first validates its complete manifest and derives RAM14
from it. It then mixes the existing instance/manifest binding and enters the
core helper with RAM already selected. The helper mixes the explicit domain
`WSRD`, revision 1, tuple width 14. It draws the local register, FUNCTION, ROM,
OWNER, U16/U8, AND/SHIFT and selection challenges in their existing order. It
never mixes the old local RAM tag or draws the unused local offset and fourteen
coefficients. The supplied RAM relation is used directly. No Worker, request,
packet, CLI or receiver API accepts a caller-supplied challenge.

This applies to the base global protocol, nonshared Keccak through that base,
shared Keccak single/bounded truth modes, secp and combined services. Their
existing family-specific manifest RAM/crypto derivations remain unchanged.
The separate closed draw used only to construct a cost-accounting component
roster is not an accepting global draw and remains unchanged.

This is an intentional global transcript change. Local CPU challenges and CPU
proofs change. Fixed/MAIN commitments and the complete stage-one manifest do
not change for the same witness/key. Shared truth proofs may remain identical
because their own manifest-derived challenges and transcripts did not change.
A new receiver must reject old global CPU proofs rather than select a fallback
based on producer metadata. The core closed default and legacy protocols are
not revised. There is no new VM/profile enum or durable alpha input.

Tests freeze the old closed sequence, compare all returned fields and following
channel draws, and compare the shared sequence against an explicit model that
skips the unused relation. A countermodel that still draws and discards it must
produce a different selection stream. All five global authority callers are
checked against the shared core model and reject changed/incomplete manifests
without advancing their caller channel. Accepting physical proof/fresh receiver
and mutation qualification is required before adoption; kernel/circuit or
recursion coverage alone is not global acceptance.
