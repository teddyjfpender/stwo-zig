# Native-block hash work and timing scenarios

[D] Exact arithmetic over source-generated shapes from accepted M6 bundle declarations (aa46090aa). [E] Timing scenarios calibrated to the measured fast32 P2/prefixedBlake rectangular benchmarks. These are NOT measured block timings, a confidence interval, hardware bounds, a new P2 accepted profile or a complete request forecast.

Source log blowup is1 (current M6 native beta1). MAIN/INTER/composition commitments are charged on every proof. Warm omits only initialization of FIXED roots; cold charges all four trees. Composition follows source per-role degree split and8*2^split base columns. MAIN/INTER totals are independently reconciled against the source census.

| Block | Native proofs | Warm P2 GPU-s scenario | Warm Blake GPU-s scenario | Cold P2 GPU-s scenario |
|---|---:|---:|---:|---:|
|24628607|17|0.855–2.315|0.040–0.121|0.998–2.700|
|26235156|11|0.588–1.592|0.028–0.085|0.685–1.854|

The native-height prefix assumption is ESSENTIAL. CPU0 of24628607 has3606MAIN columns and maxcoefficientlog22; lifting all columns to LDE23 gives about121GB of inputs for that tree alone. The current Blender-backed native code already absorbs source-height groups into eager unfinalized Blake prefix banks. A P2 counterpart is not implemented/qualified; its proposed bank carries24M31 state words plus a source-owned absorb position. The operation model assumes exact prefix reuse and full retained Merkle layers. Flat all-column rehashing is separately reported and is not a practical fallback.

A P2 leaf absorbs in rate12, permutes on each complete rate block and always adds the marker/final permutation. A parent hashes18canonical limbs and costs2permutations. Existing Blake uses eager full-block compression at nonfinal source heights, defers the final block, then1compression per interior node. Single-height models reconcile exactly with the measured benchmark framing; the eager16low-height+1high-height case is explicitly checked. A corrected eager convention lowers the early Blake forecast by a few percent relative to an initial deferred-only sketch.

Native cold LDE output volumes, shared by either hash at unchanged geometry, are40.638GiB for24628607 and28.488GiB for26235156. Warm volumes are38.708GiB and27.156GiB. These are exact output work volumes, NOT simultaneous memory or GPU time. The JSON also reports a defined cell×log(row) work index; it is not an exact butterfly count. No measured LDE timing is available in this artifact, so no FFT budget is invented.

Calibration uses observed extrema across log>=17 rectangular benchmark cases; small-bank occupancy, state-bank read/write, launch overhead and mixed-source layouts are not directly calibrated. Native FS/PoW, openings, transfers, allocation, source witness and host waiting remain excluded. The current23-node outer P2 budget is UNAVAILABLE: variable count alone does not define component geometry, and a five-step candidate leaf is not substituted for every Ethereum leaf/fold.

The new kernel is slower in relative terms but its absolute native-only hash scenario is roughly1–2GPU-s, not automatically a complete-system no-go. A decision needs the corresponding actual per-class pure P2 recursive cell census, an implemented prefix runtime with joined global admission, and matched full-block latency. Current receipt evidence does not establish those outcomes.
