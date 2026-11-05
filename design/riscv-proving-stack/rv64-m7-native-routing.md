# M7 frozen native routing falsifier

Status: optional and unpromoted. `STWO_RV64_NATIVE_ROUTING=balanced` freezes a source-derived mapping before GPU work. A bounded longest-first assignment uses the sum of both stages’ peak-byte admission estimates, honors per-owner CPU-scope capacity, and supplies the identical affinity map to both stage schedulers and all router callbacks. Original ordinal and publication order are preserved. The default remains cyclic.

The balanced production run completed six requests across both dev blocks. All native bins, bundles, recursive proofs and trees were byte-identical to M6; fresh cache-disabled CPU receivers accepted both blocks. Router tests passed 19 cases and scheduler tests passed two cases, including sparse queues, rejected invalid maps and retained owner identity across both stages.

Warm native medians were 3.2745 s on block 26235156 and 4.841 s on 24628607. This did not improve the preceding compact parallel cyclic run (3.0085 s / 4.4535 s). The same-binary cyclic control failed the last warm headline request under the shared 22 GiB carve after five requests completed, preventing a qualified complete paired timing comparison. Source admission estimates are a proxy, and no actual GPU load-balance improvement is claimed. Preserve this negative result and prioritize native GKR’s structural column reduction.

Evidence lives in `vectors/reports/rv64-m7-20261105/native-routing/`: exact source hashes, full producer receipt, M6 parity fingerprints, focused test logs and cyclic failure log. The built driver SHA256 is `3d824cf81a9c3519e24d0423ad8e5c02261a48ab45970766340ee247a45967d8`.
