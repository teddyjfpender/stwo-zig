window.BENCHMARK_FULL_DATA = {
  "rows": [
    {
      "family": "bit_rev",
      "rust_prove_avg_seconds": 0.06491743066666666,
      "rust_verify_avg_seconds": 0.0001871253333333333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.94464,
      "zig_over_rust_verify": 7.47271,
      "zig_prove_avg_seconds": 0.12624100000000002,
      "zig_verify_avg_seconds": 0.0013983333333333332
    },
    {
      "family": "eval_at_point",
      "rust_prove_avg_seconds": 0.06890488866666666,
      "rust_verify_avg_seconds": 0.00020043066666666667,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.797957,
      "zig_over_rust_verify": 7.171225,
      "zig_prove_avg_seconds": 0.123888,
      "zig_verify_avg_seconds": 0.0014373333333333332
    },
    {
      "family": "barycentric_eval_at_point",
      "rust_prove_avg_seconds": 0.06763006966666667,
      "rust_verify_avg_seconds": 0.00019915233333333334,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.857221,
      "zig_over_rust_verify": 6.797142,
      "zig_prove_avg_seconds": 0.12560400000000002,
      "zig_verify_avg_seconds": 0.0013536666666666669
    },
    {
      "family": "eval_at_point_by_folding",
      "rust_prove_avg_seconds": 0.06677816666666665,
      "rust_verify_avg_seconds": 0.00019565266666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.821289,
      "zig_over_rust_verify": 6.661465,
      "zig_prove_avg_seconds": 0.12162233333333333,
      "zig_verify_avg_seconds": 0.0013033333333333334
    },
    {
      "family": "fft",
      "rust_prove_avg_seconds": 0.06633625,
      "rust_verify_avg_seconds": 0.00020358366666666666,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.793901,
      "zig_over_rust_verify": 6.421602,
      "zig_prove_avg_seconds": 0.11900066666666666,
      "zig_verify_avg_seconds": 0.0013073333333333333
    },
    {
      "family": "field",
      "rust_prove_avg_seconds": 0.067309778,
      "rust_verify_avg_seconds": 0.000204222,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.775819,
      "zig_over_rust_verify": 6.499463,
      "zig_prove_avg_seconds": 0.11952999999999998,
      "zig_verify_avg_seconds": 0.0013273333333333334
    },
    {
      "family": "fri",
      "rust_prove_avg_seconds": 0.067601556,
      "rust_verify_avg_seconds": 0.00020479166666666668,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.795235,
      "zig_over_rust_verify": 6.396745,
      "zig_prove_avg_seconds": 0.12136066666666667,
      "zig_verify_avg_seconds": 0.0013100000000000002
    },
    {
      "family": "lookups",
      "rust_prove_avg_seconds": 0.06724248633333334,
      "rust_verify_avg_seconds": 0.000208306,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.762566,
      "zig_over_rust_verify": 6.232818,
      "zig_prove_avg_seconds": 0.11851933333333332,
      "zig_verify_avg_seconds": 0.0012983333333333332
    },
    {
      "family": "merkle",
      "rust_prove_avg_seconds": 0.06849116666666667,
      "rust_verify_avg_seconds": 0.000174014,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 3.13749,
      "zig_over_rust_verify": 7.208232,
      "zig_prove_avg_seconds": 0.21489033333333332,
      "zig_verify_avg_seconds": 0.0012543333333333334
    },
    {
      "family": "prefix_sum",
      "rust_prove_avg_seconds": 0.068299361,
      "rust_verify_avg_seconds": 0.00020477733333333333,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 1.982444,
      "zig_over_rust_verify": 8.459595,
      "zig_prove_avg_seconds": 0.13539966666666667,
      "zig_verify_avg_seconds": 0.0017323333333333333
    },
    {
      "family": "pcs",
      "rust_prove_avg_seconds": 0.068803208,
      "rust_verify_avg_seconds": 0.00018645833333333332,
      "zig_over_rust_proof_wire_bytes": 1.0,
      "zig_over_rust_prove": 2.043519,
      "zig_over_rust_verify": 9.442682,
      "zig_prove_avg_seconds": 0.14060066666666668,
      "zig_verify_avg_seconds": 0.0017606666666666667
    }
  ],
  "schema_version": 1,
  "source_report": "vectors/reports/benchmark_full_report.json",
  "summary": {
    "avg_zig_over_rust_prove": 1.973826,
    "avg_zig_over_rust_verify": 7.160334,
    "failure_count": 0,
    "families": 11,
    "max_zig_over_rust_prove": 3.13749,
    "max_zig_over_rust_verify": 9.442682
  }
};
