# canon-native adversarial review 1 (2026-11-04, reviewed 7c289553a)

No forgery found against `rv64-m5-native-chi-chain/v1` on today's (receiver re-derives everything) route.
Fixed on the branch: an unknown `STWO_RV64_NATIVE_VERSION` aborted the receiver (exit 134, corpus P03 = FAIL) -> now a clean
`error: UnknownNativeVersion` (exit 1) [M]. Added a native-side state-continuity assert in `chain.assign` (defence in depth for
binding 4.1 rule 5) and a checked `ls_count` cast. Fixed receiver accepts the chain-seed 26235156 proof (43.8 s, load 13, one
observation) [M]. Open findings (not fixed, reported): see the design doc, section 8.1.
