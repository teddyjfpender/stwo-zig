window.BENCHMARK_FULL_DATA = {
  "rows": [
    {
      "family": "bit_rev",
      "rust_prove_avg_seconds": 0.066611694,
      "rust_verify_avg_seconds": 0.00019443033333333334,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 2.001035,
      "zig_over_rust_verify": 7.733704,
      "zig_prove_avg_seconds": 0.13329233333333332,
      "zig_verify_avg_seconds": 0.0015036666666666664
    },
    {
      "family": "eval_at_point",
      "rust_prove_avg_seconds": 0.06618215266666667,
      "rust_verify_avg_seconds": 0.00019876366666666666,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 2.00204,
      "zig_over_rust_verify": 8.108457,
      "zig_prove_avg_seconds": 0.13249933333333333,
      "zig_verify_avg_seconds": 0.0016116666666666666
    },
    {
      "family": "barycentric_eval_at_point",
      "rust_prove_avg_seconds": 0.06838105566666668,
      "rust_verify_avg_seconds": 0.000198653,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 2.032103,
      "zig_over_rust_verify": 5.886311,
      "zig_prove_avg_seconds": 0.13895733333333335,
      "zig_verify_avg_seconds": 0.0011693333333333332
    },
    {
      "family": "eval_at_point_by_folding",
      "rust_prove_avg_seconds": 0.066262125,
      "rust_verify_avg_seconds": 0.000191889,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.806502,
      "zig_over_rust_verify": 6.302255,
      "zig_prove_avg_seconds": 0.11970266666666667,
      "zig_verify_avg_seconds": 0.0012093333333333333
    },
    {
      "family": "fft",
      "rust_prove_avg_seconds": 0.074773486,
      "rust_verify_avg_seconds": 0.00019369466666666667,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.658837,
      "zig_over_rust_verify": 7.045453,
      "zig_prove_avg_seconds": 0.124037,
      "zig_verify_avg_seconds": 0.0013646666666666668
    },
    {
      "family": "field",
      "rust_prove_avg_seconds": 0.06711348633333333,
      "rust_verify_avg_seconds": 0.00020061166666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.668646,
      "zig_over_rust_verify": 5.885334,
      "zig_prove_avg_seconds": 0.11198866666666667,
      "zig_verify_avg_seconds": 0.0011806666666666667
    },
    {
      "family": "fri",
      "rust_prove_avg_seconds": 0.06704936166666667,
      "rust_verify_avg_seconds": 0.00019219433333333332,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.644634,
      "zig_over_rust_verify": 7.459464,
      "zig_prove_avg_seconds": 0.11027166666666666,
      "zig_verify_avg_seconds": 0.0014336666666666664
    },
    {
      "family": "lookups",
      "rust_prove_avg_seconds": 0.06632898633333334,
      "rust_verify_avg_seconds": 0.00018763866666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.883671,
      "zig_over_rust_verify": 7.09875,
      "zig_prove_avg_seconds": 0.124942,
      "zig_verify_avg_seconds": 0.0013319999999999999
    },
    {
      "family": "merkle",
      "rust_prove_avg_seconds": 0.06661173599999999,
      "rust_verify_avg_seconds": 0.00019237533333333332,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.774677,
      "zig_over_rust_verify": 6.206617,
      "zig_prove_avg_seconds": 0.11821433333333332,
      "zig_verify_avg_seconds": 0.001194
    },
    {
      "family": "prefix_sum",
      "rust_prove_avg_seconds": 0.06531448599999999,
      "rust_verify_avg_seconds": 0.00020144433333333333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.91468,
      "zig_over_rust_verify": 6.039717,
      "zig_prove_avg_seconds": 0.12505633333333332,
      "zig_verify_avg_seconds": 0.001216666666666667
    },
    {
      "family": "pcs",
      "rust_prove_avg_seconds": 0.06524015266666668,
      "rust_verify_avg_seconds": 0.000196097,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.784423,
      "zig_over_rust_verify": 6.423692,
      "zig_prove_avg_seconds": 0.116416,
      "zig_verify_avg_seconds": 0.0012596666666666667
    }
  ],
  "schema_version": 1,
  "source_report": "vectors/reports/benchmark_full_report.json",
  "summary": {
    "avg_zig_over_rust_prove": 1.83375,
    "avg_zig_over_rust_verify": 6.744523,
    "failure_count": 0,
    "families": 11,
    "max_zig_over_rust_prove": 2.032103,
    "max_zig_over_rust_verify": 8.108457
  }
};
