import argparse
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m8_bench15 as bench

NODE = ('GPU_M8_OUTER_NODE ordinal=0 device=0 leaf=true outcome=direct launches=1118 kernel_nodes=0 host_waits=1 '
        'gpu_ns=418025970 arena_peak_words=4553800832 plan_words={ 351748352, 703496704 } placement=bottom')
NODE2 = 'GPU_M8_OUTER_NODE ordinal=1 device=1 leaf=true outcome=captured launches=1 host_waits=1 gpu_ns=400000000 arena_peak_words=4000000000'
HOST = 'GPU_M8_OUTER_NODE_HOST ordinal=0 device=0 prestage_ns=391964464 launches=99999'
MEM = 'GPU_M8_OUTER_NODE_MEM ordinal=0 device=0 heap_high_words=3309229888 arena_peak_words=9999999999'
FIXED = 'GPU_M8_OUTER_FIXED ordinal=0 device=0 columns=45 outcome=direct launches=53 gpu_ns=7645887 host_waits=1'
NATIVE = ('GPU_M8_NATIVE_HYBRID stage=2 request=1 ordinal=3 device=1 gpu_ms=230.500 enqueue_ns=5 wait_ns=6 '
          'arena_peak_words=1000 host_waits=1')
EVENT = 'GPU_M8_NATIVE_HYBRID event=boot workers=2 arena_words=5 wide=true'


def request(ordinal, wall_s, latency_s):
    return {'block': 1, 'ordinal': ordinal, 'marker': {'request_wall_ns': int(wall_s * 1e9)}, 'client_latency_ns': int(latency_s * 1e9)}


COMBINED = {'capture_ns': 2_000_000_000, 'native_setup_ns': 140_000_000, 'native_prove_ns': 4_750_000_000,
            'recursion_after_native_ns': 13_200_000_000, 'recursive': {'leaf_proofs': 14, 'fold_proofs': 5, 'root_proof_bytes': 749688}}


def service(arm, role, warm_s, cold_s=None, status='ok', **extra):
    rows = [dict(proving_s=cold_s or 2 * warm_s, request_s=(cold_s or 2 * warm_s) + 0.4, capture_s=2.0, setup_s=0.1,
                 native_window_s=4.0, recursion_after_native_s=5.0, tail_s=0.5, jobs={}),
            dict(proving_s=warm_s, request_s=warm_s + 0.4, capture_s=1.5, setup_s=0.1, native_window_s=3.0,
                 recursion_after_native_s=warm_s - 5.0, tail_s=0.4, jobs={})]
    return dict(arm=arm, role=role, status=status, requests=rows, **extra)


class BasketTests(unittest.TestCase):
    def test_native_service_refuses_missing_failed_or_invalid_physical_guard(self):
        import json, tempfile
        from unittest.mock import patch
        closed = {'status': 'RELEASED', 'exit_code': 0, 'failure': [], 'sha256': 'a' * 64, 'ready': {
            'schema': 'rv64-physical-budget-guard/v1', 'ready': True, 'requested_limit_bytes': 28000000000, 'devices': [
            {'device': d, 'held_physical_bytes': 1, 'total_bytes': 28000000001, 'prover_physical_ceiling_bytes': 28000000000} for d in (0, 1)]}}
        invalid = [{}, dict(closed, status='HOLDING'), dict(closed, exit_code=1), dict(closed, exit_code=False),
                   dict(closed, failure=['early exit']), dict(closed, sha256='b' * 64), dict(closed, ready={}),
                   dict(closed, ready=dict(closed['ready'], ready=False)),
                   dict(closed, ready=dict(closed['ready'], devices=[dict(d, held_physical_bytes=0) for d in closed['ready']['devices']])),
                   dict(closed, ready=dict(closed['ready'], devices=closed['ready']['devices'][:1] * 2)),
                   dict(closed, ready=dict(closed['ready'], devices=[dict(d, prover_physical_ceiling_bytes=28000000001) for d in closed['ready']['devices']]))]
        invalid += [dict(closed, ready=v) for v in ([], 1)]
        invalid += [dict(closed, ready=dict(closed['ready'], devices=[dict(d, device=v) for d in closed['ready']['devices']])) for v in (False, [], '0')]
        with tempfile.TemporaryDirectory() as tmp:
            b = object.__new__(bench.Bench)
            b.root = b.out = Path(tmp)
            b.stream, b.preset, b.environment, b.extra_env = 'guard-test', {'common': {}, 'arms': {'baseline': {}}}, {}, {}
            b.args = argparse.Namespace(smoke=False)
            b.assets = {'assets': {'library': '/native', 'addon': '/jobs', 'outer_fs': '/fs', 'process_budget_guard': '/guard'}, 'asset_sha256': {'process_budget_guard': 'a' * 64}}
            run = Path(tmp) / 'runs/guard-test/daemon-24628607-r2-audit'
            run.mkdir(parents=True)
            with patch.object(bench, 'M3', Path(tmp)), patch.object(bench.stack, 'command', return_value=([], 'audit')), \
                    patch.object(bench, 'validate_assets'), patch.object(bench, 'validate_library_environment'), \
                    patch.object(bench.subprocess, 'run', return_value=argparse.Namespace(returncode=0)):
                for index, guard in enumerate([*invalid, closed]):
                    (run / 'receipt.json').write_text(json.dumps({'physical_budget_guard': guard, 'requests': []}))
                    entry = b.service(24628607, {'cpu_segments': 7}, 'default' if index % 2 else 'gpu-native', 'headline', 0, 1)
                    self.assertIn('--process-budget-guard', entry['argv'])
                    self.assertEqual(entry['argv'][entry['argv'].index('--process-budget-guard') + 1], '/guard')
                    if index < len(invalid):
                        self.assertEqual(entry['status'], 'failed')
                        self.assertIn('physical guard', entry['reason'])
                    else:
                        self.assertEqual(entry['physical_budget']['status'], 'ENFORCED_PHYSICAL_CEILING')
                        self.assertIsNone(entry['physical_budget']['observed_exact_process_peak_bytes'])

    def test_basket_is_fifteen_blocks_ascending_and_matches_m3_sum(self):
        rows = bench.basket()
        self.assertEqual(len(rows), 15)
        self.assertEqual([r['request_s'] for r in rows], sorted(r['request_s'] for r in rows))
        self.assertAlmostEqual(sum(r['request_s'] for r in rows), 1843.0, delta=0.5)
        self.assertEqual(rows[0]['block'], bench.SMOKE_BLOCK)
        self.assertTrue(set(bench.DEV_BLOCKS) <= {r['block'] for r in rows})

    def test_basket_refuses_a_changed_summary(self):
        with self.assertRaises(RuntimeError):
            bench.basket({'rows': [{'request_s': 1}], 'totals': {'request_s_sum_15': 1843.0}})

    def test_large_blocks_release_the_idle_pcs_cache(self):
        self.assertEqual(bench.block_environment({'cpu_segments': 39}), {})
        self.assertEqual(bench.block_environment({'cpu_segments': 40}), {'STWO_RV64_PCS_IDLE_CACHE_BYTES': '0'})

    def test_arm_environment_substitutes_assets_and_refuses_unknown_arms(self):
        assets = {'addon': '/a/libjobs.so', 'outer_fs': '/a/libfs.so'}
        default = bench.arm_environment('default', assets)
        self.assertEqual(default['STWO_RV64_M8_JOBS_LIBRARY'], assets['addon'])
        self.assertEqual(default['STWO_RV64_M8_OUTER_FS_LIBRARY'], assets['outer_fs'])
        self.assertNotIn('STWO_RV64_M8_GPU_NATIVE', default)
        self.assertNotIn('STWO_RV64_M8_JOBS', default)
        hybrid = bench.arm_environment('hybrid', assets)
        self.assertEqual(hybrid['STWO_RV64_M8_OUTER_JOBS'], '1')
        self.assertEqual(hybrid['STWO_RV64_M8_NATIVE_JOBS'], '1')
        self.assertEqual(hybrid['STWO_RV64_M8_JOBS_LIBRARY'], '/a/libjobs.so')
        self.assertTrue(all(k.startswith(('STWO_RV64_M8_', 'STWO_RV64_M9_')) for arm in bench.ARMS for k in bench.ARMS[arm]))
        native = bench.arm_environment('gpu-native', assets)
        self.assertEqual(native['STWO_RV64_M8_OUTER_FS_LIBRARY'], '/a/libfs.so')
        self.assertEqual(native['STWO_RV64_M8_GPU_NATIVE_REUSE'], '1')
        self.assertEqual(native['STWO_RV64_M9_CLASS_PACKED_INGRESS'], '1')
        with self.assertRaises(ValueError):
            bench.arm_environment('fullstack', assets)

    def test_arms_option_validation(self):
        self.assertEqual(bench.arms_type('default,outer'), ['default', 'outer'])
        for bad in ('', 'default,default', 'nope'):
            with self.assertRaises(argparse.ArgumentTypeError):
                bench.arms_type(bad)

    def test_common_environment_is_explicit_and_conflicts_fail_closed(self):
        flag = 'STWO_RV64_M8_TRUTH_SPLIT=1'
        self.assertEqual(bench.extra_environment([flag, flag]), {'STWO_RV64_M8_TRUTH_SPLIT': '1'})
        for bad in (['PATH=/tmp'], ['STWO_FLAG'], ['STWO_bad=1'], [flag, flag[:-1] + '0']):
            with self.assertRaises(ValueError):
                bench.extra_environment(bad)


class ParsingTests(unittest.TestCase):
    def test_fields_parse_ints_floats_and_braced_lists(self):
        row = bench.fields('a=1 b=2.5 c=true d={ 1, 2 } e=-3')
        self.assertEqual(row, {'a': 1, 'b': 2.5, 'c': 'true', 'd': '{ 1, 2 }', 'e': -3})

    def test_split_requests_ends_each_request_at_its_marker(self):
        text = '\n'.join(['boot', NODE, 'GPU_RESIDENT_BLOCK block=1 trial=0 iteration=0 request_wall_ns=5', NODE2,
                          'GPU_RESIDENT_BLOCK block=1 trial=1 iteration=1 request_wall_ns=4', 'shutdown'])
        parts = bench.split_requests(text)
        self.assertEqual(len(parts), 2)
        self.assertIn(NODE, parts[0])
        self.assertEqual(parts[1][0], NODE2)

    def test_nested_install_proofs_do_not_become_request_metrics(self):
        text = '\n'.join(['GPU_RESIDENT_SERVICE ready init_ns=1 runtime=inner', NODE,
                          'GPU_RESIDENT_BLOCK block=1 iteration=0 request_wall_ns=900',
                          'GPU_RESIDENT_SERVICE ready init_ns=1000 runtime=m8-gpu-native',
                          'GPU_RESIDENT_SETUP begin block=1', NODE,
                          'GPU_RESIDENT_SETUP reclaim device=0 persistent_words=1024 retained_words=0',
                          'GPU_RESIDENT_BLOCK block=1 iteration=0 request_wall_ns=900',
                          'GPU_RESIDENT_SETUP end block=1 setup_ns=200 status=accepted',
                          'actual-first', 'GPU_RESIDENT_BLOCK block=1 iteration=0 request_wall_ns=5',
                          'actual-second', 'GPU_RESIDENT_BLOCK block=1 iteration=1 request_wall_ns=4'])
        setups = []
        parts = bench.split_requests(text, setups)
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0][0], 'actual-first')
        self.assertEqual(parts[1][0], 'actual-second')
        self.assertNotIn(NODE, [line for part in parts for line in part])
        self.assertEqual(setups[0]['setup_ns'], 200)
        self.assertIn(NODE, setups[0]['lines'])
        other = []
        self.assertEqual(parts, bench.split_requests(text.replace('SETUP begin block=1', 'SETUP begin block=2').replace('SETUP end block=1', 'SETUP end block=2'), other))
        self.assertEqual(other[0]['block'], 2)
        failed = []
        self.assertEqual([], bench.split_requests(text.split('actual-first')[0].replace('status=accepted', 'status=failed'), failed))
        self.assertEqual(failed[0]['status'], 'failed')
        for changed in (text.replace('end block=1', 'end block=2'), text.replace('end block=1', 'begin block=1'),
                        text.replace('GPU_RESIDENT_SETUP end block=1 setup_ns=200 status=accepted', ''),
                        text.replace('setup_ns=200', 'setup_ns=-1'), text.replace('status=accepted', 'status=unknown'),
                        text.replace('SETUP begin block=1', 'SETUP begin block=-1')):
            with self.assertRaises(ValueError):
                bench.split_requests(changed)

    def test_job_metrics_count_only_job_lines(self):
        jobs = bench.job_metrics([NODE, NODE2, HOST, MEM, FIXED, NATIVE, EVENT])
        node = jobs['outer_node']
        self.assertEqual(node['count'], 2)  # NODE_HOST / NODE_MEM are not nodes
        self.assertEqual(node['launches']['sum'], 1119)
        self.assertEqual(node['launches']['max'], 1118)
        self.assertEqual(node['host_waits']['median'], 1)
        self.assertAlmostEqual(node['gpu_s'], 0.818, places=3)
        self.assertEqual(node['peak_bytes'], 4553800832 * 4)
        self.assertEqual(jobs['outer_fixed']['launches']['sum'], 53)
        native = jobs['native_stage']
        self.assertEqual(native['count'], 1)  # event= lines are not jobs
        self.assertAlmostEqual(native['gpu_s'], 0.2305, places=4)
        self.assertIsNone(native['launches'])
        self.assertEqual(bench.job_metrics(['nothing here']), {})

    def test_request_metrics_stages_and_derived_tail(self):
        row = bench.request_metrics(request(1, 20.13, 20.57), COMBINED, [NODE])
        self.assertEqual(row['proving_s'], 20.13)
        self.assertEqual(row['request_s'], 20.57)
        self.assertEqual(row['native_window_s'], 4.75)
        self.assertEqual(row['recursion_after_native_s'], 13.2)
        self.assertAlmostEqual(row['tail_s'], 20.13 - 2.0 - 0.14 - 4.75 - 13.2, places=3)
        self.assertEqual(row['nodes'], 19)
        self.assertEqual(row['jobs']['outer_node']['count'], 1)
        partial = bench.request_metrics(request(0, 30.0, 31.0), {'capture_ns': 1}, [])
        self.assertIsNone(partial['tail_s'])
        self.assertIsNone(partial['nodes'])

    def test_native_receipt_keeps_driver_spans_separate_from_unknown_stage_partitions(self):
        native = {'schema': 'rv64-m8-gpu-native-request/v1', 'block': 1, 'sequence': 1, 'request_wall_ns': 10_000_000_000,
            'setup_ns': 2_000_000_000, 'setup_plus_request_ns': 12_000_000_000, 'receipt': {
            'host_waits': 1, 'd2h': 2, 'd2h_bytes': 1234,
            'device_gpu_us': [8_000_000, 9_000_000, 0, 0],
            'device_enqueue_ns': [7_000_000_000, 8_000_000_000, 0, 0],
            'device_gate_ns': [10_000_000, 20_000_000, 0, 0],
            'device_memory_serializations': [3, 4, 0, 0]}}
        lines = ['GPU_RESIDENT_BLOCK block=1 iteration=1 request_wall_ns=10000000000 setup_ns=2000000000 setup_plus_request_ns=12000000000']
        row = bench.request_metrics(request(1, 10.0, 10.1), {'native_prove_ns': None}, lines, native)
        self.assertEqual((row['setup_miss_s'], row['setup_plus_request_s']), (2.0, 12.0))
        self.assertEqual(row['driver']['device_span_s'], [8.0, 9.0])
        self.assertEqual(row['driver']['device_enqueue_s'], [7.0, 8.0])
        self.assertEqual(row['driver']['memory_serializations'], [3, 4])
        self.assertEqual(row['driver']['host_waits'], 1)
        self.assertIsNone(row['driver']['job_slab_d2h'])
        self.assertIsNone(row['driver']['host_callbacks'])
        self.assertIsNone(row['native_window_s'])
        self.assertIsNone(row['tail_s'])
        self.assertEqual(row['jobs'], {})
        for key, value in (('block', 2), ('sequence', 0), ('request_wall_ns', 9), ('setup_ns', -1),
                           ('setup_ns', True), ('setup_plus_request_ns', 11_000_000_000)):
            with self.assertRaises(ValueError):
                bench.request_metrics(request(1, 10.0, 10.1), {}, lines, dict(native, **{key: value}))
        with self.assertRaises(ValueError):
            bench.request_metrics(request(1, 10.0, 10.1), {}, [lines[0].replace('iteration=1', 'iteration=2')], native)
        with self.assertRaises(ValueError):
            bench.request_metrics(request(1, 10.0, 10.1), {}, ['GPU_RESIDENT_BLOCK block=1 iteration=1 request_wall_ns=10000000000 setup_ns=-1 setup_plus_request_ns=9999999999'], dict(native, setup_ns=-1, setup_plus_request_ns=9999999999))
        legacy = {k: v for k, v in native.items() if k not in ('setup_ns', 'setup_plus_request_ns')}
        row = bench.request_metrics(request(1, 10.0, 10.1), {}, [lines[0].split(' setup_ns=')[0]], legacy)
        self.assertIsNone(row['setup_miss_s'])
        self.assertIsNone(row['setup_plus_request_s'])

    def test_profile_metrics_busy_and_per_node_counts(self):
        out = bench.profile_metrics({'kernel_busy_gpu_seconds': 10.0, 'any_busy_gpu_seconds': 12.0},
                                    {'cudaLaunchKernel': 19000, 'cudaStreamSynchronize': 190}, 19, 25.0)
        self.assertEqual(out['kernel_gpu_s'], 10.0)
        self.assertEqual(out['gpu_busy'], 0.2)
        self.assertEqual(out['launches_per_node'], 1000.0)
        self.assertEqual(out['syncs_per_node'], 10.0)
        self.assertEqual(bench.profile_metrics(None, None, 19, 25.0), {'profiled_proving_s': 25.0})


class AggregationTests(unittest.TestCase):
    def test_aggregate_arm_medians_exclude_failed_and_profiled_services(self):
        services = [service('outer', 'headline', 20.0, device_peak_bytes=30e9, nvml_kernel_active_percent=14.0),
                    service('outer', 'headline', 22.0, device_peak_bytes=31e9, nvml_kernel_active_percent=16.0),
                    service('outer', 'headline', 21.0),
                    service('outer', 'headline', 99.0, status='failed'),
                    service('outer', 'profile', 40.0, profile={'kernel_gpu_s': 9.0})]
        services[2]['requests'][1]['jobs'] = bench.job_metrics([NODE, NODE2])
        services[0]['per_gpu_sampled_max_used_bytes'] = {'0': 30e9, '1': 29e9}
        services[1]['per_gpu_sampled_max_used_bytes'] = {'0': 31e9, '1': 28e9}
        arm = bench.aggregate_arm(services)
        self.assertEqual(arm['warm']['n'], 3)
        self.assertEqual(arm['warm']['proving_s'], 21.0)
        self.assertEqual(arm['cold']['proving_s'], 42.0)
        self.assertEqual(arm['device_peak_bytes_sampled'], 31e9)
        self.assertEqual(arm['per_gpu_sampled_max_used_bytes'], {'0': 31e9, '1': 29e9})
        self.assertEqual(arm['nvml_kernel_active_percent'], 15.0)
        self.assertEqual(arm['profile_warm'], {'kernel_gpu_s': 9.0})
        self.assertEqual(arm['per_node_peak_bytes'], 4553800832 * 4)
        self.assertEqual(arm['job_launches_per_node'], 559.5)
        self.assertEqual(arm['job_syncs_per_node'], 1)

    def test_aggregate_totals_count_only_done_blocks_and_compare_m3(self):
        rows = bench.basket()
        small, dev = rows[0], next(r for r in rows if r['block'] == 24628607)
        blocks = {small['block']: {'block': small['block'], 'status': 'done', 'parity': {'requests_identical': 4},
                                   'services': [service('default', 'headline', 10.0), service('outer', 'headline', 16.0)]},
                  dev['block']: {'block': dev['block'], 'status': 'done',
                                 'services': [service('default', 'headline', 13.0)]},
                  rows[-1]['block']: {'block': rows[-1]['block'], 'status': 'failed',
                                      'services': [service('default', 'headline', 50.0)]}}
        result = bench.aggregate(blocks, ['default', 'outer'], rows)
        self.assertEqual(result['schema'], bench.SCHEMA)
        self.assertEqual(len(result['blocks']), 15)
        totals = result['totals']
        self.assertEqual(totals['default']['blocks'], 2)  # the failed block is excluded
        self.assertEqual(totals['default']['warm_proving_s_sum'], 23.0)
        self.assertEqual(totals['default']['cold_proving_s_sum'], 46.0)
        self.assertAlmostEqual(totals['default']['m3_request_s_sum_same_blocks'], small['request_s'] + dev['request_s'], places=2)
        self.assertEqual(totals['outer']['blocks'], 1)
        by_block = {b['block']: b for b in result['blocks']}
        self.assertEqual(by_block[24628607]['m7']['warm_proving_s'], 12.9)
        self.assertEqual(by_block[rows[5]['block']]['status'], 'not_run')
        text = bench.markdown(result)
        self.assertIn('| 26235156 |', text)
        self.assertIn('10.00 / 20.00', text)
        self.assertIn('| outer | 1 |', text)
        self.assertEqual(text.count('\n| 24628607 | default |'), 1)

    def test_distribution_is_nearest_rank(self):
        values = list(range(1, 16))  # 15 blocks
        self.assertEqual(bench.distribution(values), {'n': 15, 'p50': 8, 'p90': 14, 'max': 15})
        self.assertEqual(bench.distribution([3.0]), {'n': 1, 'p50': 3.0, 'p90': 3.0, 'max': 3.0})
        self.assertIsNone(bench.distribution([None]))

    def test_arm_failure_reason_prefers_the_named_error(self):
        log = 'GATE boot\nsomething failed here\nerror: GpuNativeNativeShapeHookMissing\n/x/driver_serve.zig:103: in install\n'
        self.assertEqual(bench.arm_failure_reason(log), 'error: GpuNativeNativeShapeHookMissing')
        self.assertEqual(bench.arm_failure_reason('a\nservice never READY: M8RequestProviderNotLanded\n'),
                         'service never READY: M8RequestProviderNotLanded')

    def test_producer_tail_reads_plain_and_gzipped_stderr(self):
        import gzip, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bench.producer_tail(tmp), '')
            (Path(tmp) / 'producer.stderr.gz').write_bytes(gzip.compress(b'x\nerror: GpuNativeNativeShapeHookMissing\n'))
            text = 'service exited before READY (1)\n' + bench.producer_tail(tmp)
            self.assertEqual(bench.arm_failure_reason(text), 'error: GpuNativeNativeShapeHookMissing')

    def test_arm_failures_are_reported_and_excluded_from_totals(self):
        rows = bench.basket()
        small = rows[0]
        failure = {'kind': 'service', 'reason': 'error: GpuNativeNativeShapeHookMissing', 'run': 'r', 'log': 'l'}
        blocks = {small['block']: {'block': small['block'], 'status': 'done', 'arm_failures': {'gpu-native': failure},
                                   'services': [service('default', 'headline', 10.0),
                                                dict(arm='gpu-native', role='headline', status='failed')]}}
        result = bench.aggregate(blocks, ['default', 'gpu-native'], rows)
        self.assertEqual(result['arm_failures'], {'gpu-native': [small['block']]})
        self.assertNotIn('gpu-native', result['totals'])
        self.assertEqual(result['totals']['default']['warm_proving_s'], {'n': 1, 'p50': 10.0, 'p90': 10.0, 'max': 10.0})
        text = bench.markdown(result)
        self.assertIn('10.00 / 20.00 | FAIL |', text)
        self.assertIn('gpu-native FAILED (service)', text)
        self.assertNotIn('| gpu-native | -', text)

    def test_estimate_is_monotonic_in_block_size_and_labelled(self):
        rows = bench.basket()
        estimate = bench.estimate_walls(rows, ['default', 'outer', 'native', 'hybrid', 'jobs'], 3)
        self.assertEqual(estimate['label'], 'E')
        walls = [estimate['arms']['default']['blocks'][r['block']]['warm_s'] for r in rows]
        self.assertEqual(walls, sorted(walls))
        dev = estimate['arms']['default']['blocks'][24628607]
        self.assertAlmostEqual(dev['warm_s'], 12.8, places=1)
        self.assertGreater(estimate['arms']['outer']['gpu_wall_s'], estimate['arms']['default']['gpu_wall_s'])
        lighter = bench.estimate_walls(rows, ['default'], 1, profile=False)
        self.assertLess(lighter['arms']['default']['gpu_wall_s'], estimate['arms']['default']['gpu_wall_s'])


class ToleratedArmTests(unittest.TestCase):
    def setUp(self):
        self.free_bytes = bench.free_bytes
        bench.free_bytes = lambda path: 1 << 50

    def tearDown(self):
        bench.free_bytes = self.free_bytes

    def bench(self, tmp, outcomes):
        b = object.__new__(bench.Bench)
        b.out = Path(tmp)
        b.args = argparse.Namespace(rounds=3, arms=['default', 'gpu-native'], tolerate_arm_failure=['gpu-native'],
                                    receivers='reference', profile='warm', quiet_retries=0, min_free_gb=0)
        calls = []

        def fake_service(block, row, arm, role, round_index, attempt):
            calls.append((arm, role, round_index))
            log = Path(tmp) / f'{arm}-{role}-{round_index}.log'
            status = outcomes(arm, role)
            log.write_text('error: GpuNativeNativeShapeHookMissing\n' if status != 'ok' else 'ok\n')
            return {'arm': arm, 'role': role, 'round': round_index, 'run': str(Path(tmp) / 'none' / f'{arm}{round_index}'),
                    'status': status, 'log': str(log), 'exit_code': 0 if status == 'ok' else 1,
                    'requests': [{'proving_s': 1.0, 'nodes': 1}, {'proving_s': 1.0, 'nodes': 1}]}

        def fake_parity(block, entry, state):
            state['reference'] = state.get('reference') or {'run': entry['run']}

        b.service = fake_service
        b.parity = fake_parity
        b.receive = lambda block, run: [{'accepted': True}]
        b.gpu_seconds = lambda entry, ref: {'kernel_gpu_s': 1.0}
        b.prune = lambda run, keep_proofs=False: None
        return b, calls

    def test_failed_tolerated_arm_is_recorded_once_and_the_block_completes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'blocks').mkdir()
            b, calls = self.bench(tmp, lambda arm, role: 'failed' if arm == 'gpu-native' else 'ok')
            state = b.block({'block': 26235156})
        self.assertEqual(state['status'], 'done')
        self.assertEqual(calls.count(('gpu-native', 'headline', 0)), 1)
        self.assertNotIn(('gpu-native', 'headline', 1), calls)
        self.assertNotIn(('gpu-native', 'profile', 0), calls)
        self.assertEqual([c for c in calls if c[0] == 'default'],
                         [('default', 'headline', 0), ('default', 'headline', 1), ('default', 'headline', 2), ('default', 'profile', 0)])
        self.assertEqual(state['arm_failures']['gpu-native']['reason'], 'error: GpuNativeNativeShapeHookMissing')

    def test_untolerated_arm_failure_still_stops(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'blocks').mkdir()
            b, _ = self.bench(tmp, lambda arm, role: 'failed' if arm == 'default' else 'ok')
            with self.assertRaises(bench.Stop) as stop:
                b.block({'block': 26235156})
        self.assertIn('GpuNativeNativeShapeHookMissing', str(stop.exception))


if __name__ == '__main__':
    unittest.main()
