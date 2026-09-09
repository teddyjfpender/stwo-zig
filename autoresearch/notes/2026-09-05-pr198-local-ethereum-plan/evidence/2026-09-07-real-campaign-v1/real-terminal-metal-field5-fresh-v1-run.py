import fcntl, hashlib, json, pathlib, subprocess, sys, time
repo = pathlib.Path.cwd()
base = repo / '.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907'
produced = base / 'metal-field5-segment120-production-v2'
exe = repo / '.git/local-ethereum/fixed-program-native-verifier-v1/bin/ethereum-full-leaf-bundle-verify-v1'
out = repo / '.git/local-ethereum/selected-real-metal-terminal-field5-fresh-v1'
materialization = base / 'authority/materialization-v2.json'
def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()
with open('/tmp/stwo-zig-build.lock', 'a+') as lock:
    print('waiting for shared lock', flush=True)
    fcntl.flock(lock, fcntl.LOCK_EX)
    producer = json.loads((produced / 'receipt.json').read_text())
    if not producer['verified_and_published']:
        raise SystemExit('Metal producer has not published a verified artifact')
    proof = pathlib.Path(producer['artifact']['path'])
    metadata = pathlib.Path(producer['global_metadata']['path'])
    pins = {str(exe): 'a63bec79ffafd2ed489b90317357039f38b03ce05e6e0ddd40bbbd84a29245d2', str(proof): producer['artifact']['sha256'], str(metadata): producer['global_metadata']['sha256'], str(materialization): 'e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e'}
    if not all(sha(pathlib.Path(path)) == digest for path, digest in pins.items()):
        raise SystemExit('Independent verifier input pin mismatch')
    out.mkdir()
    command = [str(exe), 'verify-leaf-fixed-program-v5', str(proof), str(metadata), str(materialization), pins[str(materialization)], '--workers', '1']
    (out / 'run.py').write_bytes(pathlib.Path(__file__).read_bytes())
    (out / 'plan.json').write_text(json.dumps({'command': command, 'input_sha256': pins, 'endpoint': 'verified_native_selected_leaf_fixed_program_v5', 'producer_process_destroyed': True, 'full_block_coverage': False}, indent=2) + '\n')
    started = time.monotonic_ns()
    with (out / 'stdout.json').open('xb') as stdout, (out / 'stderr-and-time.log').open('xb') as stderr:
        result = subprocess.run(['/usr/bin/time', '-l', *command], stdout=stdout, stderr=stderr, timeout=1200)
    elapsed = time.monotonic_ns() - started
    unchanged = all(sha(pathlib.Path(path)) == digest for path, digest in pins.items())
    parsed = json.loads((out / 'stdout.json').read_text()) if result.returncode == 0 else None
    verification = parsed['verification'] if parsed else None
    passed = result.returncode == 0 and unchanged and parsed['endpoint'] == 'verified_native_selected_leaf_fixed_program_v5' and verification['segment_index'] == 120 and verification['segment_count'] == 121 and verification['worker_count'] == 1 and verification['proof_bytes'] == producer['artifact']['bytes'] and verification['retained_admission_destroyed_before_proof']
    receipt = {'passed': passed, 'exit_code': result.returncode, 'elapsed_ns': elapsed, 'producer_process_destroyed': True, 'inputs_and_binary_unchanged': unchanged, 'verification': parsed, 'full_block_coverage': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
    sys.exit(0 if passed else 1)
