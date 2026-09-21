# Recursive parent device interactions

The shared parent producer now generates all 29 typed interaction components on
the admitted Metal AOT backend. Existing CPU preparation remains available.
The 29 fraction kernels share three cumulative scan kernels: intermediate
columns accumulate within each row, and the last column uses a cross-row prefix
shifted by the average claim. Equations and local input bindings come from the
authenticated shared AIR exporter. Logical-to-physical projection has one owner.

Qualification includes:
- Focused independent and cumulative GPU scans over five geometries, block
  carries, nontrivial extension-field challenges, padding and rejection/recovery.
- All 29 parent AIRs through the real authenticated AOT loader, compared against
  CPU columns and claims with full and padded rows; rejected calls preserve
  destination columns and permit a successful retry.
- Six native lookup tables through the same updated AOT bundle.
- Four-segment CPU/Metal production, producer exit, fresh-process verification
  and hostile cases: 192 per backend. All 21 serialized artifacts match each
  other and the canonical baseline.
- Measured dispatch requirements: 96 native-table dispatches for four leaves,
  348 typed-interaction dispatches for three parents.
- Fourteen shared-owner and verifier-dependency checks.

Parent Poseidon and range provider interaction generation remain on CPU.
The host bridge still stages canonical columns and copies successful device
output back to the commitment ABI. These are development receipts, not a claim
of production security, Ethereum readiness, or a measured speedup.
