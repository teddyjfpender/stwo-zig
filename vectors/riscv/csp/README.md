# Retained CSP contract fixture

`riscv_csp_benchmark_report.json` is byte-identical to
`4e260db9605d16fef5d405cc3c280e3042b22e35:vectors/reports/riscv_csp_benchmark_report.json`.
SHA-256: `b1c9c5673f315cf4a9e8abd3da617fb3ab47342961b2672f68364fbed357e655`.

The live `RetainedReportTests` in `scripts/tests/test_riscv_csp_benchmark.py`
use its schema, workload binding and proof validation cases. Retain it until
those consumers retire. This is a historical fixture, not a measurement of
the current checkout or evidence for GPU promotion.
