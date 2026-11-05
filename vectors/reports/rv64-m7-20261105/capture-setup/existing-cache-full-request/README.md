# Existing identity-only setup route: full M6 request gate

PASS:8/8 complete development-block requests match every pinned M6 native proof, bundle, recursive proof and tree artifact. Four separate cache-disabled, GPU-disabled CPU receiver processes accept. Same frozen eba08050 driver,69f18a25 CUDA runtime and0434da78 receiver in both conditions; full M6 v3 producer preset, graph/controller/shared-RC paths OFF. No new experimental bitmap/class-order/eager flags are in the selected binary.

| M: block | cold request off → on | cold setup off → on | warm request off → on | root bytes unchanged |
|---|---:|---:|---:|---:|
|26235156|27.682 →24.335s|8.911 →4.857s|12.712 →11.836s|750,136|
|24628607|40.155 →34.554s|12.631 →6.946s|18.614 →18.200s|708,696|

Cold request reductions are3.347s(12.09%) and5.601s(13.95%). Cold setup reductions are45.49% and45.01%. Each condition has one cold and one warm request from an isolated service. These are measured paired samples, not a robust multi-seed timing claim. Warm setup was already tiny (.137→.125s small;.155→.214s headline), so there is no qualified warm improvement; most observed warm wall differences occur in other stages. No large-block extrapolation or fresh-receiver speed claim follows.

The only candidate toggle is the EXISTING `STWO_ZIG_RV64_SETUP_CACHE=''`. Environment presence selects resident SetupCache; the empty value means directory=null, so no persisted artifacts are read or written. This activates the existing identity-only CPU source and parallel immutable-class construction. It avoids redundant source-key commitment work while preserving the complete receiver-derived candidate fixed authority. `--store none` applies in both conditions. Four fresh receiver walls were35.166/35.483s small and53.004/50.970s headline; all independently derive authority with caches disabled.

Every selected asset hash is checked before every service and again at collection. The controller also checked the complete source snapshot before every service. Root subsequently replaced the pod source checkout at about09:57UTC with9531c5c16 for a different build, after this run completed. The30 changed/removed source paths are retained in post-collection-source-drift.json; the selected driver/runtime/receiver never changed. selected-driver-frozen-provenance.json records the original df39+graph-fix compiled source attestation. Do not label the current checkout as that compiled snapshot. Binary identity, complete M6 artifact parity and fresh receiver closure remain the qualification basis.

All producer and receiver raw reports, resource manifests, command arrays, exact source/asset hashes, pair comparisons and M6 comparisons are retained beside this file. Native/recursive binary artifacts remain at the immutable pod paths in the raw receipts. Harness owns the GPU lock; no enclosing lock was used. No new large-block run or source build was needed.
