# Private word payloads in canonical frames

Transfer the existing symbolic digest router to word payload provenance. Native
Frame.write remains the only byte-order owner. Optional protocolWord callbacks
mark leaf M31 words, secure-field coordinates and raw word payloads, with indexed
roles; ordinary hash sinks receive identical little-endian bytes.

Extend the shared router with one checked payload range, alongside its existing
digest roles. Count actual word consumers, including unaligned frame boundaries.
Reject mismatched role/length, namespace aliasing and missing producer endpoints.
Reuse the routed-frame witness and canonical field encoder; do not add a second
byte-routing AIR or private serializer. Native hash vectors must remain unchanged.

Validate framed leaf hashing from authenticated QM31 coordinates in a complete
CPU proof, placeholder-independent preprocessing, malformed bindings, and native
protocol vectors. Source tuple is public in the fixture; this demonstrates framed
arithmetic payload wiring, not full child-proof source admission. No speed claim.
