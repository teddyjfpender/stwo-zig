# Real Ethereum windows: original proofs and one recursive root

These cases execute the pinned Ethereum guest from independently selected, complete incoming machine-state capsules. They prove declared **nonterminal windows** with outgoing state continuity. They do not prove the skipped prefix or an entire Ethereum block. The original SSZ-derived input is included for provenance; the window request uses the selected incoming state rather than replaying that input.

`original-window-times.csv` contains original-proof sets. `recursive-window-times.csv` contains separately qualified final roots. All use canonical 70-query / 26-bit-PoW settings. Timings are individual controlled observations, not statistical estimates.

## Canonical 32K recursive root

`native-32768-composed-root` proves 32,768 actual guest cycles after one externally admitted skipped cycle. One native proof, ROM, compact lookup and nonterminal joint memory produce four original proofs. The original owners are destroyed before the final recursive root is freshly verified with complete global closure.

| Phase | Seconds |
|---|---:|
| Complete request | 66.8396 |
| Original source work excluding recursive consumer | 4.4981 |
| Recursive preparation and proving | 60.4487 |
| Independent final root verification | 1.8020 |
| Recursive cold key (included above) | 8.2632 |
| Recursive capture/witness/join (included above) | 11.3900 |
| Recursive proving (included above) | 36.5962 |

The 1,023,252-byte root has SHA256 `8ee14e8654e498f5c154dfc700a76cc8da1dbfbddb266c7cc7fd46ac9ccde400`. Tracked peak is 13,860,470,724 bytes and measured RSS is 13,901,398,016 bytes. This run uses 12 workers, one 32K segment, degree-bounded-q2 layout, sparse initialization, resident memory, a 2GiB native MAIN cache and 4MiB native DEEP grouping. Cold compilation uses four family workers. Sparse initialization retains the full snapshot endpoint theorem; selected addresses only narrow which initial values may be first-touched.

The source report's `consumer_ns` includes recursion. Never add `source.whole_ns` to `recursive.whole_ns`. The CSV computes source work as `source.whole_ns - source.consumer_ns`.

The exact invocation-pinned build receipt is `composed-recursive-build/build-invocation.json`; `build.json` additionally links the full source manifest. The binary SHA is `01a67eb494c42444c305a4607f983778ebd7a9d443358b6a1016e301c81efb30`; source snapshot SHA is `d7e06ae504157b3a6d526f0998faad412037275ce32be9fbe0b6570df0692b48`. This measured run does not rerun hostile controls; those remain separate focused qualification gates.

## Original-proof controls

All five corpus cases have original-proof qualification: native32K, native128K, native512K, recovery32K (32 Keccak + 6 recovery calls), and Keccak32K (228 Keccak calls). Only native32K currently has the final recursive-root qualification above.

For the same native512K capsule, increasing segment size reduced 35 originals to five: 66.47s at 16K segments/four workers, 40.44s at 256K/four workers, and 30.67s at 256K/twelve workers. The latter two produce byte-identical original proof sets. The composed q2/sparse/resident/cache/DEEP configuration measured 14.58s with five originals. These are original-proof request latencies, not final recursive-root latencies. No composed recovery/Keccak improvement has yet been measured.

Logical checkpoint writes are measured; checkpoint reads and physical disk I/O remain explicitly uninstrumented. Compressed/decompressed capsule bytes and logical ELF loads are separate from checkpoint bytes. Native profiling stages are inclusive: child times must not be added to their parents.

## Reproduction and portability

Run `python3 scripts/v7_real_window_results.py --report-dir vectors/reports/block-v7-real-window-v2-20261030` to revalidate saved proof/input/build pins and regenerate the CSVs. `prepared-corpus.json` selects all five capsule pairs. `runpod-corpus-manifest.json` includes compressed file hashes, decoded-file hashes and distinct state-identity hashes; these are deliberately not conflated.

The corpus archive contains no host executable or credentials. Linux semantic compilation passed with Zig 0.15.2 and `-target x86_64-linux-gnu -mcpu=baseline`; this is compilation evidence only, not GPU qualification. See `design/riscv-proving-stack/performance/v7-runpod-portable-corpus.md` for the source snapshot and CUDA build recipe.
