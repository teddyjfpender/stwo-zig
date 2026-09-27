"""Build and qualify the standalone receiver against a retained canonical root.

The saved report is trusted test setup only. A real receiver must obtain its
expected key from its own admission configuration, never a received report.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from zig_serial_build import build_lock

out = HERE / 'block-receiver-qualification-v1'
out.mkdir(exist_ok=False)
binary = out / 'block-verify'
with (out / 'build.log').open('x') as log:
    subprocess.run([sys.executable, str(HERE / 'build_stream_memory_lifetimes.py'),
                    '--root', 'src/frontends/riscv/ethereum_block_verify.zig',
                    '--output', str(binary)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
fixture = HERE / 'measurements-auth1-canonical-stages'
report = fixture / 'proof-report.json'
proof = fixture / 'root.proof'
setup = json.loads(report.read_text())
expected = bytes(setup['admission']['expected_id']).hex()
checks = []


def check(name, proof_path, report_path, pin, expected_success, expected_error=None):
    command = [str(binary), str(proof_path), str(report_path), pin]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    (out / (name + '.stdout')).write_text(result.stdout)
    (out / (name + '.stderr')).write_text(result.stderr)
    if expected_success:
        if result.returncode or json.loads(result.stdout)['complete_execution_proof_verified'] is not True:
            raise RuntimeError(f'{name}: valid retained root did not verify')
    elif not result.returncode or (expected_error and expected_error not in result.stderr):
        raise RuntimeError(f'{name}: expected rejection not observed')
    checks.append({'case': name, 'exit_code': result.returncode, 'expected_success': expected_success})


with build_lock(label='ethereum-block-receiver-qualification'):
    check('valid-canonical-root', proof, report, expected, True)
    wrong = ('01' if expected[:2] != '01' else '02') + expected[2:]
    # Missing proof path proves that key admission happens before proof I/O.
    check('wrong-key-before-proof-open', out / 'absent.proof', report, wrong, False, 'UntrustedBlake3ParentKey')
    check('malformed-key-before-proof-open', out / 'absent.proof', report, 'xx' * 32, False, 'InvalidTrustedKeyHex')
    changed = json.loads(report.read_text())
    changed['admission']['key']['config']['pow_bits'] = 0
    changed_report = out / 'changed-security.json'
    changed_report.write_text(json.dumps(changed))
    check('changed-security', proof, changed_report, expected, False, 'InvalidBlake3ParentProfile')
    truncated = out / 'truncated.proof'
    truncated.write_bytes(proof.read_bytes()[:20])
    check('truncated-proof', truncated, report, expected, False, 'TruncatedBlake3ParentArtifact')
    changed_bytes = bytearray(proof.read_bytes())
    changed_bytes[-1] ^= 1
    corrupted = out / 'corrupted.proof'
    corrupted.write_bytes(changed_bytes)
    check('corrupted-proof', corrupted, report, expected, False)
    files = [binary, proof, report, ROOT / 'src/frontends/riscv/ethereum_block_verify.zig']
    (out / 'qualification.json').write_text(json.dumps({
        'scope': 'fresh-process receiver on a canonical authentication fixture; not a mainnet block proof',
        'checks': checks,
        'sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
    }, indent=2) + '\n')
print(json.dumps(checks, indent=2))
