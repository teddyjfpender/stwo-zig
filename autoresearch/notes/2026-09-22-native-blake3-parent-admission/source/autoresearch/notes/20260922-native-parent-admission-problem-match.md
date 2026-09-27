# Explicit BLAKE3 native-parent key and transcript admission

Reuse the existing detached-parent rule: key identities do not authorize
anything unless the verifier pins them independently. Add a separate BLAKE3
native-child parent identity that commits suite, version, diagnostic profile,
child PCS configuration, child statement/authority, all five graph identities,
transcript plan, typed roster semantics/geometry, relation registry, and fixed
preprocessing root. SHA-256 is structural artifact identity, not Fiat-Shamir.
Absorb the admitted identity and profile before commitments using the native
BLAKE3 channel. The pinned root must reject substitution before proof verification.

This is ordered canonical serialization and exact equality admission, linear in
the fixed roster. No new hash or algebraic algorithm is needed. Keep the current
q8/PoW0 diagnostic profile explicit: it does not authorize production q193 keys
or alter old Poseidon artifacts. Qualify the new transcript with the complete
native-parent proof; mutate version, profile config, root, graph and expected
pin. Retain the shared existing standalone gate through its original protocol.
