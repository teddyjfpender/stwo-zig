# rv64-m9-io-design receipts

Supporting files for `design/riscv-proving-stack/rv64-m9-io-streaming.md`. Research only: no GPU was used. Hashes are in
`SHA256SUMS`.

| path | what |
|---|---|
| `telemetry/24628607-contributions-producer-grep.txt` | read-only `grep -n` of `producer.stderr` from pod run `daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-06-baseline` (pack/unpack, assignment, staging, projection lines). The last two lines are the sha256 of that `producer.stderr` (`3a5a6d57…`) and of its `nsys/timeline.sqlite` (`04573fd8…`). Line numbers are those of `producer.stderr`. |
| `queries/h2d_overlap.py`, `queries/h2d_range.py` | read-only sqlite queries used for overlap and NVTX-range attribution over that trace |
| `zkdtvm/article-reader-proxy.md` | zkDTVM announcement article, rendered through a reader proxy on 2026-11-07 (the page is a JS SPA) |
| `zkdtvm/fig4-architecture.png` | article figure "End-to-end GPU acceleration architecture" (source of "executor: rv2x86 AOT") |
| `zkdtvm/fig5-cluster.png` | article figure "Distributed multi-shard proving" (source of `GpuExecutionRecord: Checkpoint \| MemoryGlobal \| Precompile`, bincode, `SubProveRequest`) |
| `zkdtvm/zkdtvm-docker-README.md`, `zkdtvm/zkdtvm-docker-prove_network_coordinator.sh` | `AntChainOpenLabs/zkdtvm-docker @ 861bbb07`; the per-GPU `--cpuset-cpus`/`--cpuset-mems` pinning is in the script (ll.27-41), not the README |
| `ethproofs/clusters-20261107.md`, `ethproofs/team-antchain-openlabs-20261107.md` | EthProofs `/clusters` (redirects to `/provers`) and team page snapshots, 2026-11-07 |
