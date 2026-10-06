#!/usr/bin/env bash
set -euo pipefail

s31_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$s31_dir/../../.." && pwd)"
cairo_dir="$s31_dir/examples/cairo"
mkdir -p "$repo_root/zig-out/s31"
report_dir="$(mktemp -d "$repo_root/zig-out/s31/compare.XXXXXX")"

cd "$repo_root"
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
zig build --build-file src/frontends/s31/build.zig install -Doptimize=ReleaseFast
zig build --build-file src/frontends/s31/build.zig showcase -Doptimize=ReleaseFast 2>&1 | tee "$report_dir/s31.log"
cp zig-out/s31/affine4.proof "$report_dir/s31.proof"
src/frontends/s31/zig-out/bin/s31-affine4-verifier "$report_dir/s31.proof" 1 2 3 65535
if src/frontends/s31/zig-out/bin/s31-affine4-verifier "$report_dir/s31.proof" 1 2 3 65534 >"$report_dir/changed-public.log" 2>&1; then
  echo "S31 verifier accepted a changed public input" >&2
  exit 1
fi
python3 - "$report_dir/s31.proof" "$report_dir/s31-tampered.proof" <<'PY'
import pathlib
import sys
data = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
data[len(data) // 2] ^= 1
pathlib.Path(sys.argv[2]).write_bytes(data)
PY
if src/frontends/s31/zig-out/bin/s31-affine4-verifier "$report_dir/s31-tampered.proof" 1 2 3 65535 >"$report_dir/tampered-proof.log" 2>&1; then
  echo "S31 verifier accepted a modified proof" >&2
  exit 1
fi

scarb --manifest-path "$cairo_dir/Scarb.toml" test
scarb --manifest-path "$cairo_dir/Scarb.toml" build
scarb --manifest-path "$cairo_dir/Scarb.toml" execute --no-build \
  --arguments '1,2,3,65535' --output none --print-program-output --print-resource-usage \
  2>&1 | tee "$report_dir/cairo-execute.log"

cargo run --release --locked --manifest-path "$repo_root/tools/stwo-cairo-vm-adapter-rs/Cargo.toml" -- \
  run --program "$cairo_dir/target/dev/s31_affine4_cairo.executable.json" \
  --program-type executable --arguments "$cairo_dir/arguments.json" \
  --prover-input-out "$report_dir/cairo-input.json"
zig build stwo-cairo-cpu -Doptimize=ReleaseFast
zig-out/bin/stwo-cairo-cpu prove --prover-input "$report_dir/cairo-input.json" \
  --proof "$report_dir/cairo-proof.json" --proof-format json \
  --report-out "$report_dir/cairo-report.json" --verify

python3 - "$report_dir" <<'PY'
import json
import pathlib
import re
import sys

report_dir = pathlib.Path(sys.argv[1])
public = [1, 2, 3, 65535, 18, 25, 32, 458756]
cairo_proof = json.loads((report_dir / 'cairo-proof.json').read_text())
actual = [word[1][0] for word in cairo_proof['claim']['public_data']['public_memory']['output']]
if actual != public:
    raise SystemExit(f'Cairo public output differs: {actual}')
config = cairo_proof['stark_proof']['config']
fri = config['fri_config']
expected_fri = {'pow_bits': 26, 'log_blowup_factor': 1, 'log_last_layer_degree_bound': 0, 'n_queries': 70, 'fold_step': 1}
actual_fri = {'pow_bits': config['pow_bits'], **{key: fri[key] for key in expected_fri if key != 'pow_bits'}}
if actual_fri != expected_fri:
    raise SystemExit(f'Cairo FRI settings differ: {actual_fri}')
cairo_report = json.loads((report_dir / 'cairo-report.json').read_text())
if not cairo_report['verification']['zig']:
    raise SystemExit('Cairo native verifier did not accept the proof')
s31_log = (report_dir / 's31.log').read_text()
match = re.search(r'field-ops=(\d+)->(\d+), Blake-G=(\d+)->(\d+), proof=(\d+) bytes, setup=([0-9.]+)s, prove=([0-9.]+)s, total through verification=([0-9.]+)s', s31_log)
if not match:
    raise SystemExit('S31 showcase metrics missing')
raw_field, padded_field, raw_blake, padded_blake, proof_bytes, setup_s, prove_s, total_s = match.groups()
execution_log = (report_dir / 'cairo-execute.log').read_text()
steps = re.search(r'steps:\s*(\d+)', execution_log)
summary = {
    'schema': 's31-cairo-smoke-v0',
    'public_words': public,
    'fri_visible_settings': expected_fri,
    's31': {
        'proof_bytes_binary': int(proof_bytes),
        'raw_field_op_rows': int(raw_field),
        'padded_field_op_rows': int(padded_field),
        'raw_blake_g_rows': int(raw_blake),
        'padded_blake_g_rows': int(padded_blake),
        'setup_seconds': float(setup_s),
        'prove_seconds': float(prove_s),
        'total_through_verification_seconds': float(total_s),
        'native_verified': True,
        'changed_public_rejected': True,
        'tampered_proof_rejected': True,
    },
    'cairo': {
        'vm_steps': int(steps.group(1)) if steps else None,
        'proof_bytes_json': cairo_report['proof']['bytes'],
        'prove_seconds': cairo_report['timing']['prove_ns'] / 1e9,
        'request_through_publication_seconds': cairo_report['timing']['request_until_publication_ns'] / 1e9,
        'peak_physical_footprint_bytes': cairo_report['prover_process_usage']['lifetime_peak_physical_footprint_bytes'],
        'native_verified': True,
    },
    'comparison_limit': 'Different proof protocols, verifier implementations, encodings and preprocessing policies; one stochastic PoW sample.',
}
(report_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
print(f'Artifacts: {report_dir}')
PY
