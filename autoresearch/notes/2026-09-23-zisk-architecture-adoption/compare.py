"""Historical CSP gap census; does not qualify a promotion or run benchmarks."""
import hashlib
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "vectors/reports/recursive-product-20260921/csp-accelerated-suite-v1"
CURRENT = ROOT / "autoresearch/notes/2026-09-23-parallel-column-projection"


def fingerprint(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    rows = []
    for backend in ("cpu", "metal"):
        baseline = BASE / f"{backend}.json"
        for old in json.loads(baseline.read_text())["measurements"]:
            target, size = old["target"], old["input_size"]
            record = {"backend": backend, "target": target, "size": size,
                      "baseline": fingerprint(baseline),
                      "baseline_mean_prove_seconds": old["proof_duration"] / 1e9,
                      "baseline_peak_bytes": old["peak_memory"],
                      "status": "missing_current_subset_measurement"}
            path = CURRENT / f"{backend}-{target}-{size}-candidate.json"
            if path.exists():
                new = json.loads(path.read_text())
                assert new["backend"] == backend
                assert new["elf_sha256"] == old["evidence"]["guest_sha256"]
                assert new["input_sha256"] == old["evidence"]["input_sha256"]
                # Historical suite publishes raw 32-byte output; native report hashes it.
                expected_output = bytes.fromhex(old["evidence"]["output_digest"])
                assert new["output_len"] == len(expected_output)
                assert new["output_sha256"] == hashlib.sha256(expected_output).hexdigest()
                config = old["protocol"]["pcs_config"]
                assert new["pcs_config"]["fri_config"] == config["fri_config"]
                assert new["pcs_config"]["pow_bits"] == config["pow_bits"]
                assert config.get("lifting_log_size") is None
                assert new["pcs_config"].get("lifting_log_size") is None
                assert new["verified_in_process"] and new["verified_samples"] == new["samples"]
                samples = [sum(t[k] for k in ("execution_ns", "witness_ns", "proving_ns")) / 1e9
                           for t in new["timings"]]
                mean = statistics.mean(samples)
                record.update(current=fingerprint(path), status="historical_diagnostic_only",
                              current_mean_prove_seconds=mean,
                              current_over_baseline=mean / record["baseline_mean_prove_seconds"],
                              current_samples=new["samples"], current_warmups=new["warmups"],
                              current_peak_bytes=new["resources"]["after_verified_samples"]["lifetime_max_phys_footprint_bytes"])
            rows.append(record)
    result = {"scope": "execution + witness + proving; excludes admission/encoding/verification",
              "qualification": False,
              "limitations": ["Historical runs; original 1 warmup/10 samples versus current 0/3.",
                              "Subset only; no full-suite win or matched memory qualification.",
                              "Peak is process-lifetime physical footprint including verification.",
                              "Worker/build/host identities are documented in the source evidence; current native report workers is null."],
              "rows": rows}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
