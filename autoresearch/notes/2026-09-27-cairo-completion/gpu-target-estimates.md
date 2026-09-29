# CUDA GPU research targets (2026-09-28)

These are conditional engineering targets, not GPU measurements. The user reports an earlier 1.5-second H100 proof; the user now tentatively identifies it as SN PIE 2; security parameters and timing boundaries have not yet been matched to a receipt. For this provisional model assume SN PIE 2, canonical 70 queries / 26-bit PoW, retained setup, a fully resident CUDA prover including GPU witness and LogUp, and adapted execution already available. Do not multiply the recent CPU witness speedups into a CUDA route that already implemented those operations natively.

The current v31 M5 Max profiles have GPU-heavy stage wall sums of 11.191 / 5.609 / 11.319 / 6.718 seconds for PIEs 1 / 2 / 3 / 4. These include host staging and synchronization and are workload-ratio evidence, not pure GPU kernel time. Use broad approximate factors 2 / 1 / 2 / 1.2, then allow for mixed integer compute, bandwidth, occupancy and synchronization rather than treating tensor FLOPS as usable prover throughput.

| Fully resident warm prover target | VRAM | PIE 1 | PIE 2 | PIE 3 | PIE 4 |
| --- | --- | --- | --- | --- | --- |
| H100 SXM | 80 GB | 2–4 s | 1–2 s | 2–4 s | 1.2–2.5 s |
| H200 SXM | 141 GB | 1.6–3.2 s | 0.8–1.6 s | 1.6–3.2 s | 1–2 s |
| B200 SXM | 180 GB | 1–2.4 s | 0.5–1.2 s | 1–2.4 s | 0.6–1.5 s |
| RTX PRO 6000 Blackwell workstation | 96 GB | 3.6–7 s | 1.8–3.5 s | 3.6–7 s | 2.2–4.5 s |

NVIDIA specifications: H100/H200/B200 capacities and 3.35/4.8/up-to-8 TB/s bandwidth from https://docs.nvidia.com/enterprise-reference-architectures/hgx-ai-factory-h100-h200-b200/latest/components.html ; RTX PRO 6000 workstation 96 GB / 1.792 TB/s from https://www.nvidia.com/content/dam/en-zz/Solutions/data-center/rtx-pro-6000-blackwell-workstation-edition/workstation-blackwell-rtx-pro-6000-workstation-edition-nvidia-us-3519208-web.pdf . Hardware specifications support capacity/bandwidth statements, not these timing targets.

Whole-product Metal physical peaks in v31 are 61.209 / 37.153 / 60.543 / 45.399 decimal GB. These include CPU and Metal allocations and cannot be substituted for CUDA VRAM plans. The July CUDA checkpoint records a roughly 58.029 GB SN2 resident allocation, not an accepted end-to-end proof. H100 fits that SN2 plan; fitting the larger PIEs needs actual CUDA lifetime planning and the bounded-memory improvements. H200/B200 are safer capacity candidates. A 96 GB workstation may support all four after porting, but this is unqualified. Single 24 GB 4090 / 32 GB 5090 devices need a different bounded/streamed plan. Multiple GPUs need explicit distribution; VRAM is not automatically pooled.

A practical benchmark server has 32–64 fast CPU cores, at least 128 GB host RAM and preferably 256 GB for development and concurrent-job headroom, full memory channels, and PCIe 5.0 connectivity. This is a configuration target rather than a measured minimum.

ZIP-to-proof times additionally include official VM execution/adaptation, currently about 2.4 seconds for SN2 and 4–5 seconds for larger PIEs. Today's CPU witness and interaction generation also remain multi-second phases. Achieving the table requires resident GPU implementations and scheduling, not just replacing the Metal PCS backend. Multi-GPU latency forecasts remain deferred until distribution/communication measurements exist.
