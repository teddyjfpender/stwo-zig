#!/usr/bin/env python3
"""Both-dev proof-byte/fresh gate for bounded CPU assignment retirement."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--profile', choices=['d2', 'm6'], default='d2')
    parser.add_argument('--repeat', type=int, choices=[1, 2], default=2)
    parser.add_argument('--nsys', action='store_true')
    parser.add_argument('--block', type=int, choices=[26235156, 24628607], action='append')
    parser.add_argument('--async-retire', choices=['0', '1'], default='1')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'scripts'))
    import rv64_resident_basket as basket
    args.out.mkdir(parents=True, exist_ok=True)

    def snapshot(path, leaves):
        return dict(native={p.name: sha(p) for p in sorted(path.glob('*.bin'))},
                    bundle=sha(path / 'bundle.json'), recursive=basket.recursive_snapshot(path, leaves))

    rows = []
    for block in args.block or [26235156, 24628607]:
        suffix = 'combined-d2-coalesce-v1' if args.profile == 'd2' else 'combined-m6-v3'
        reference = Path(f'/workspace/m3/runs/m7-fold-v3/daemon-{block}-r2-{suffix}')
        baseline = json.loads((reference / 'receipt.json').read_text())
        plan = json.loads((reference / 'plan.json').read_text())
        expected = snapshot(Path(baseline['requests'][0]['proof']), baseline['requests'][0]['leaves'])
        assets = plan['assets']
        assert sha(assets['library']) == 'a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45'
        tag = f'assignment-retire-{args.async_retire}-{args.profile}' + ('-nsys' if args.nsys else '')
        # The harness stream names its synced source as well as its run root;
        # receipt output may be placed in a separate profiling directory.
        stream = root.name
        run = Path('/workspace/m3/runs') / stream / f'daemon-{block}-r{args.repeat}-{tag}'
        command = [sys.executable, str(root / 'scripts/rv64_m4_resident.py'), 'daemon', str(block),
                   '--stream', stream, '--build-stream', 'm7-callback-retire',
                   '--repeat', str(args.repeat), '--store', 'none', '--receive', 'first', '--tag', tag,
                   '--driver', args.driver, '--library', assets['library'], '--receiver', assets['receiver'],
                   '--no-default-env']
        if args.profile == 'd2':
            command += ['--security-profile', 'd2_native_b4_q54_p20_fold4', '--coalesce-truth-families']
        if args.nsys:
            command += ['--nsys']
        environment = dict(plan['environment'])
        environment.update(STWO_RV64_PACK_FOLD_CACHE='1', STWO_RV64_OUTER_RETIRE_ASYNC=args.async_retire)
        for name, value in sorted(environment.items()):
            command += ['--env', name + '=' + value]
        (args.out / f'{block}-{tag}-command.json').write_text(json.dumps(command, indent=2) + '\n')
        with open(args.out / f'{block}-{tag}.log', 'w') as log:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=900)
        assert result.returncode == 0, (block, result.returncode, run)
        receipt = json.loads((run / 'receipt.json').read_text())
        assert len(receipt['requests']) == args.repeat
        assert len(receipt['receivers']) == 1
        fresh = receipt['receivers'][0]
        assert fresh['accepted'] is True and fresh['status'] == 'accepted'
        assert fresh['process']['exit_code'] == 0 and fresh['block'] == block and fresh['trial'] == 0
        assert fresh['receiver_sha256'] == sha(assets['receiver'])
        assert fresh['store_present_during_receive'] is False
        assert fresh['isolation']['CUDA_VISIBLE_DEVICES'] == ''
        assert fresh['isolation']['STWO_RV64_GPU_PCS_HELPER'] == '/bin/false'
        assert fresh['isolation']['STWO_ZIG_RV64_SETUP_CACHE'] == 'unset'
        for request in receipt['requests']:
            actual = snapshot(Path(request['proof']), request['leaves'])
            assert actual == expected, (block, request['trial'], actual.keys())
        text = (run / 'producer.stderr').read_text()
        spans = re.findall(r'GPU_OUTER_ASSIGNMENT_RETIRE ordinal=(\d+) dispatch_ns=(\d+) worker_ns=(\d+) join_wait_ns=(\d+) async=true', text)
        nodes = sum(len(json.loads((Path(r['proof']) / 'recursion-om31/pipeline.json').read_text())['nodes']) for r in receipt['requests'])
        if args.async_retire == '1':
            assert len(spans) == nodes and all(int(row[2]) > 0 for row in spans), (len(spans), nodes)
            admissions = re.findall(r'GPU_OUTER_RETIRE_WORKERS total=(\d+) pool=(\d+) dedicated=(\d+) lanes_per_device=(\d+)', text)
            assert admissions and all(int(pool) + int(dedicated) == int(total) and int(dedicated) == 2 and int(lanes) == 1 for total, pool, dedicated, lanes in admissions)
        else:
            assert not spans
        row = dict(block=block, all_artifacts_byte_identical=True, reference=str(reference),
                   receipt=str(run / 'receipt.json'), fresh_receivers=receipt['receivers'],
                   nodes=nodes, retirement_spans=spans, driver_sha256=sha(args.driver),
                   scope='Correctness and owner spans; no request-time claim without matched ownership analysis')
        rows.append(row)
        (args.out / f'{block}-{tag}-gate.json').write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps(dict(block=block, requests=args.repeat, nodes=nodes, artifacts_identical=True)), flush=True)
    (args.out / f'gate-{args.profile}-{args.async_retire}.json').write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
