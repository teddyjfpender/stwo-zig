"""Pinned single-candidate operation; never calls the campaign production loop."""
import fcntl
import hashlib
import json
from pathlib import Path
import sys
import time


def identity(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            size += len(chunk)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def main():
    request_path, request_sha = sys.argv[1:]
    if identity(request_path)['sha256'] != request_sha:
        raise ValueError('one-candidate request changed')
    request = json.loads(Path(request_path).read_bytes())
    source = Path(request['source'])
    for item in request['custody']:
        if identity(item['path']) != item['identity']:
            raise ValueError('request custody changed: ' + item['path'])
    manifest = json.loads((source.parent / 'manifest.json').read_bytes())
    for item in manifest['files']:
        if identity(source / item['path']) != {k: item[k] for k in ('bytes', 'sha256')}:
            raise ValueError('frozen Python closure changed: ' + item['path'])
    sys.path.insert(0, str(source))
    from scripts import ethereum_block_proof_protocol as protocol
    from scripts import ethereum_block_proof_store as store
    from scripts import ethereum_bounded_verifier as bounded
    from scripts.ethereum_full_leaf_bundle_producer import validate_leaf_receipt

    def check_custody():
        for item in request['custody']:
            store.validate_file_identity(Path(item['path']), item['identity'], 'single-candidate custody')
        for item in manifest['files']:
            store.validate_file_identity(source / item['path'], {k: item[k] for k in ('bytes', 'sha256')}, 'frozen Python source')

    campaign = Path(request['campaign'])
    index = request['segment_index']
    argv = request['verifier_argv']
    metadata_path = Path(argv[3])
    leaf_path = campaign / f'leaf-{index:06d}.json'
    attempt = Path(request['attempt'])
    staging = campaign / '.staging'
    def publish(path, value):
        store.publish_new_or_identical(path, protocol.canonical_bytes(value), staging_directory=staging)

    with (campaign / 'controller.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_custody()
        protocol.require(not leaf_path.exists(), 'candidate is already accepted; refusing duplicate verification')
        plan = store.read_canonical_json(campaign / 'plan.json', 'sealed campaign')
        leaf = json.loads(store.read_regular(metadata_path, 'producer metadata', maximum=128 * 1024))
        protocol.require(leaf['metadata']['segment_index'] == index, 'candidate position differs')
        protocol.require(argv == [plan['verifier']['path'], 'verify-leaf-fixed-program-v5',
                         str(campaign / (bytes(leaf['proof_sha256']).hex() + '.bin')),
                         str(metadata_path), plan['materialization']['path'],
                         plan['materialization']['sha256'], '--workers', str(plan['workers'])],
                         'single-candidate command differs from campaign')
        producer = metadata_path.parent
        producer_request = store.read_canonical_json(producer / 'request.json', 'producer request')
        protocol.require(producer_request['plan_sha256'] == protocol.sha256_bytes(protocol.canonical_bytes(plan)), 'candidate campaign differs')
        protocol.require(store.read_canonical_json(producer / 'execution.json', 'producer execution')['exit_code'] == 0, 'producer did not succeed')
        policy = bounded.load_policy(Path(request['policy']), request['policy_sha256'])
        attempt.mkdir(exist_ok=False)
        publish(attempt / 'request.json', {'argv': argv, 'plan_sha256': producer_request['plan_sha256'],
                'verification_policy_sha256': request['policy_sha256'], 'single_candidate_request_sha256': request_sha})
        observation = {'policy_sha256': request['policy_sha256']}
        execution = {}
        started = time.monotonic_ns()
        try:
            with (attempt / 'stdout.json').open('xb') as stdout, (attempt / 'stderr.log').open('xb') as stderr:
                result = bounded.run(argv, policy, stdout=stdout, stderr=stderr, timeout=policy['timeout_seconds'], observation=observation)
            execution['exit_code'] = result.returncode
            check_custody()
            protocol.require(result.returncode == 0, 'candidate fresh verification failed')
            receipt = json.loads(store.read_regular(attempt / 'stdout.json', 'fresh receipt', maximum=128 * 1024))
            validate_leaf_receipt(receipt, index, leaf, metadata_path, plan)
        except BaseException as error:
            execution['error'] = str(error)
            raise
        finally:
            execution['process_ns'] = time.monotonic_ns() - started
            publish(attempt / 'scheduling.json', observation)
            publish(attempt / 'execution.json', execution)
        check_custody()
        publish(leaf_path, leaf)
        publish(attempt / 'result.json', {'segment_index': index, 'accepted_leaf': str(leaf_path),
                'proof_sha256': bytes(leaf['proof_sha256']).hex(), 'freshly_verified': True})
        print(f'Native segment {index} independently verified and accepted; no producer launched', flush=True)


if __name__ == '__main__':
    main()
