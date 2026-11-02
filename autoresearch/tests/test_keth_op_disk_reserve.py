import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from autoresearch.experiments.evm_keth.disk_reserve import DiskReserve


class DiskReserveTests(unittest.TestCase):
    def test_low_space_records_the_reserve_breach(self):
        with patch('autoresearch.experiments.evm_keth.disk_reserve.shutil.disk_usage',
                   return_value=SimpleNamespace(free=100)):
            guard = DiskReserve(Path('.'), 101)
            self.assertEqual(guard.check(), 'free disk fell below the explicit reserve')
            self.assertEqual(guard.record()['lowest_observed_free_bytes'], 100)

    def test_unobservable_space_rejects(self):
        with patch('autoresearch.experiments.evm_keth.disk_reserve.shutil.disk_usage', side_effect=OSError('unavailable')):
            self.assertEqual(DiskReserve(Path('.'), 1).check(), 'free-disk monitoring became unavailable')

    @unittest.skipUnless(sys.platform == 'darwin', 'footprint wrapper requires Darwin')
    def test_running_child_is_stopped_on_disk_reserve_breach(self):
        from autoresearch.experiments.evm_keth.bounded_process import run
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch('autoresearch.experiments.evm_keth.disk_reserve.DiskReserve.check',
                       side_effect=[None, 'free disk fell below the explicit reserve']):
                result = run([sys.executable, '-c', 'import time; time.sleep(2)'],
                             path/'run.log', path/'usage.json', 2**30)
            self.assertLess(result['exit_code'], 0)
            self.assertEqual(result['termination_reason'], 'free disk fell below the explicit reserve')
            self.assertFalse(result['completion_latency'])


if __name__ == '__main__':
    unittest.main()
