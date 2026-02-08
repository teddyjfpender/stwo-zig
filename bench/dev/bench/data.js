window.BENCHMARK_FULL_DATA = {
  "rows": [
    {
      "family": "bit_rev",
      "rust_prove_avg_seconds": 0.3039253606666667,
      "rust_verify_avg_seconds": 0.000256278,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.190245,
      "zig_over_rust_verify": 1.737696,
      "zig_prove_avg_seconds": 0.057820333333333335,
      "zig_verify_avg_seconds": 0.00044533333333333333
    },
    {
      "family": "eval_at_point",
      "rust_prove_avg_seconds": 0.03240213866666666,
      "rust_verify_avg_seconds": 0.00039773599999999993,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.053027,
      "zig_over_rust_verify": 1.132242,
      "zig_prove_avg_seconds": 0.034120333333333336,
      "zig_verify_avg_seconds": 0.00045033333333333335
    },
    {
      "family": "barycentric_eval_at_point",
      "rust_prove_avg_seconds": 0.066770014,
      "rust_verify_avg_seconds": 0.00021777733333333332,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.267705,
      "zig_over_rust_verify": 1.650003,
      "zig_prove_avg_seconds": 0.017874666666666667,
      "zig_verify_avg_seconds": 0.0003593333333333333
    },
    {
      "family": "eval_at_point_by_folding",
      "rust_prove_avg_seconds": 0.10627016700000001,
      "rust_verify_avg_seconds": 0.0006740833333333334,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.296974,
      "zig_over_rust_verify": 1.073062,
      "zig_prove_avg_seconds": 0.13782966666666666,
      "zig_verify_avg_seconds": 0.0007233333333333333
    },
    {
      "family": "fft",
      "rust_prove_avg_seconds": 0.107124736,
      "rust_verify_avg_seconds": 0.0006578746666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.298387,
      "zig_over_rust_verify": 1.159795,
      "zig_prove_avg_seconds": 0.13908933333333331,
      "zig_verify_avg_seconds": 0.0007630000000000001
    },
    {
      "family": "field",
      "rust_prove_avg_seconds": 0.6899692776666666,
      "rust_verify_avg_seconds": 0.00028481933333333333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.156363,
      "zig_over_rust_verify": 1.90062,
      "zig_prove_avg_seconds": 0.10788533333333333,
      "zig_verify_avg_seconds": 0.0005413333333333333
    },
    {
      "family": "fri",
      "rust_prove_avg_seconds": 0.06730656933333333,
      "rust_verify_avg_seconds": 0.00019931999999999998,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.254849,
      "zig_over_rust_verify": 1.480032,
      "zig_prove_avg_seconds": 0.017153,
      "zig_verify_avg_seconds": 0.00029499999999999996
    },
    {
      "family": "lookups",
      "rust_prove_avg_seconds": 0.14299133333333333,
      "rust_verify_avg_seconds": 0.000255333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.220783,
      "zig_over_rust_verify": 1.599219,
      "zig_prove_avg_seconds": 0.03157000000000001,
      "zig_verify_avg_seconds": 0.0004083333333333333
    },
    {
      "family": "merkle",
      "rust_prove_avg_seconds": 0.06683011100000001,
      "rust_verify_avg_seconds": 0.00023986133333333333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.271544,
      "zig_over_rust_verify": 1.731556,
      "zig_prove_avg_seconds": 0.018147333333333335,
      "zig_verify_avg_seconds": 0.0004153333333333333
    },
    {
      "family": "prefix_sum",
      "rust_prove_avg_seconds": 0.06809525033333333,
      "rust_verify_avg_seconds": 0.000183861,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.249626,
      "zig_over_rust_verify": 1.43768,
      "zig_prove_avg_seconds": 0.016998333333333334,
      "zig_verify_avg_seconds": 0.0002643333333333334
    },
    {
      "family": "pcs",
      "rust_prove_avg_seconds": 0.06704220833333334,
      "rust_verify_avg_seconds": 0.00022663866666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 0.267941,
      "zig_over_rust_verify": 1.659028,
      "zig_prove_avg_seconds": 0.01796333333333333,
      "zig_verify_avg_seconds": 0.00037600000000000003
    }
  ],
  "schema_version": 1,
  "source_report": "vectors/reports/benchmark_full_report.json",
  "summary": {
    "avg_zig_over_rust_prove": 0.502495,
    "avg_zig_over_rust_verify": 1.505539,
    "failure_count": 0,
    "families": 11,
    "max_zig_over_rust_prove": 1.298387,
    "max_zig_over_rust_verify": 1.90062
  }
};
