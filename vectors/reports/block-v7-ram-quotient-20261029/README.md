# Bounded RAM quotient evidence

These retained runtime logs cover exact original-proof parity, memory and
phase measurements for coefficient-backed RAM quotient tiles. The structured
receipt is `design/riscv-proving-stack/performance/v7-ram-tile-production-qualification-20261029.json`.

Timing comparisons are diagnostic, with different sequential runs and some
concurrent compiler activity. Helper allocation peaks, quotient scratch and
process RSS are distinct quantities. Large RAM cases use q8/PoW0; canonical
q70/PoW26 evidence is the complete-union and spill-cohort qualification. These
records do not establish whole-block throughput. Binaries are not vendored.
