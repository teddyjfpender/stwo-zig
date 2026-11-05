import itertools
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m4_resident as resident


def snapshot(pressure=0, throttled=0):
    return {'known': True, 'cpu_max': '4000000 100000',
            'cpu_pressure': {k: {'total': pressure} for k in ('some', 'full')},
            'cpu_stat': {'nr_throttled': throttled, 'throttled_usec': throttled}}


class QuietCheckpointTests(unittest.TestCase):
    def check_samples(self, snapshots, *, stable=2, timeout=300, pressure=0.0):
        ticks = itertools.count(1000, 1000)
        proc_path = Mock()
        proc_path.read_text.side_effect = lambda: f'cpu {next(ticks)} 0 0 0 0 0 0 0\n'
        proc_path.iterdir.return_value = []
        args = SimpleNamespace(quiet_load_max=8, quiet_timeout=timeout,
                               quiet_steal_max=.01, quiet_resource='cgroup',
                               quiet_pressure_max=pressure,
                               quiet_stable_samples=stable, quiet_mode='enforce')
        records = []
        with patch.object(resident, 'Path', return_value=proc_path), \
                patch.object(resident, 'cgroup_cpu_snapshot', side_effect=snapshots), \
                patch.object(resident.time, 'sleep'), \
                patch.object(resident.time, 'monotonic', side_effect=itertools.count()), \
                patch.object(resident.subprocess, 'run', return_value=SimpleNamespace(stdout='')), \
                patch.object(resident.os, 'getpgid', return_value=10), \
                patch.object(resident.os, 'getloadavg', return_value=(1, 1, 1)), \
                patch.object(resident.B, 'atomic_json', side_effect=lambda p, r: records.append(r)):
            result = resident.quiet_checkpoint(Mock(pid=10, poll=lambda: None), args, Path('/unused'), 0)
        return result, records

    def test_inventory_pressure_is_recorded_outside_idle_window(self):
        result, _ = self.check_samples([snapshot(0), snapshot(0), snapshot(50),
                                        snapshot(50), snapshot(50), snapshot(110)])
        self.assertTrue(result['accepted'])
        self.assertEqual([0, 0], [s['cgroup_delta']['psi_some_total_us'] for s in result['samples']])
        self.assertEqual([50, 60], [s['observer_cgroup_delta']['psi_some_total_us'] for s in result['samples']])

    def test_real_idle_pressure_resets_consecutive_samples(self):
        result, _ = self.check_samples([snapshot(0), snapshot(0), snapshot(20),
                                        snapshot(20), snapshot(21), snapshot(40),
                                        snapshot(40), snapshot(40), snapshot(60),
                                        snapshot(60), snapshot(60), snapshot(80)])
        self.assertEqual([True, False, True, True], [s['qualifies'] for s in result['samples']])

    def test_inventory_throttling_still_rejects(self):
        with self.assertRaisesRegex(RuntimeError, 'quiet admission timed out'):
            self.check_samples([snapshot(), snapshot(), snapshot(50, 1)], stable=1, timeout=0)

    def test_unknown_inventory_counters_still_reject(self):
        with self.assertRaisesRegex(RuntimeError, 'quiet admission timed out'):
            self.check_samples([snapshot(), snapshot(), {'known': False}], stable=1, timeout=0)

    def test_explicit_pressure_bound_uses_measured_idle_duration(self):
        for waited_us, accepted in ((500, True), (1500, False)):
            values = [dict(snapshot(0), monotonic_ns=0),
                      dict(snapshot(waited_us), monotonic_ns=1_000_000_000),
                      dict(snapshot(waited_us + 50), monotonic_ns=1_050_000_000)]
            if accepted:
                result, _ = self.check_samples(values, stable=1, timeout=0, pressure=.001)
                self.assertTrue(result['accepted'])
                self.assertEqual(.0005, result['samples'][0]['idle_pressure_fraction'])
            else:
                with self.assertRaisesRegex(RuntimeError, 'quiet admission timed out'):
                    self.check_samples(values, stable=1, timeout=0, pressure=.001)


if __name__ == '__main__':
    unittest.main()
