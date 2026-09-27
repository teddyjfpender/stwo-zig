import os
from pathlib import Path
import sys
import tempfile
import unittest
from recursive_proof_scheduler import Job, execute


def command(code):
    return (sys.executable, '-c', code)


class SchedulerTests(unittest.TestCase):
    def run_jobs(self, jobs, *, workers=2, memory=2, admit=lambda job, logs: None, timeout=3):
        with tempfile.TemporaryDirectory() as directory:
            report = {}
            execute(jobs, Path(directory) / 'logs', workers=workers, memory_bytes=memory,
                    timeout=timeout, env=dict(os.environ), admit=admit, report=report)
            return report

    def test_dependencies_wait_for_verification_and_admission(self):
        accepted = []
        def admit(job, logs):
            if job.name == 'root':
                self.assertEqual(set(accepted), {'left', 'right'})
            self.assertEqual(len(logs), 2)
            accepted.append(job.name)
        commands = (command('pass'), command('import time; time.sleep(.05)'))
        jobs = [Job('root', ('left', 'right'), commands, 1, 2),
                Job('left', (), commands, 1), Job('right', (), commands, 1)]
        report = self.run_jobs(jobs, admit=admit)
        self.assertTrue(report['passed'])
        self.assertEqual(report['maximum_active_jobs'], 2)
        root_start = report['jobs']['root']['phases'][0]['started_ns']
        self.assertGreater(root_start, max(report['jobs'][n]['completed_ns'] for n in ('left', 'right')))

    def test_memory_cap_serializes_even_with_free_workers(self):
        jobs = [Job(str(i), (), (command('import time; time.sleep(.03)'),), 2) for i in range(3)]
        report = self.run_jobs(jobs, workers=3, memory=3)
        self.assertEqual(report['maximum_active_jobs'], 1)
        self.assertEqual(report['maximum_reserved_bytes'], 2)

    def test_rejects_cycle_and_oversized_job(self):
        with self.assertRaises(ValueError):
            self.run_jobs([Job('a', ('a',), (command('pass'),), 1)])
        with self.assertRaises(ValueError):
            self.run_jobs([Job('a', (), (command('pass'),), 3)])

    def test_verifier_failure_never_admits_parent(self):
        accepted = []
        jobs = [Job('child', (), (command('pass'), command('raise SystemExit(7)')), 1),
                Job('parent', ('child',), (command('pass'),), 1)]
        with self.assertRaises(RuntimeError):
            self.run_jobs(jobs, admit=lambda job, logs: accepted.append(job.name))
        self.assertEqual(accepted, [])

    def test_failure_reaps_other_running_job(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'pid'
            sleeper = command(f'import os,time,pathlib; pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)')
            failure = command(f'import pathlib,time; p=pathlib.Path({str(pidfile)!r});\nwhile not p.exists(): time.sleep(.01)\nraise SystemExit(1)')
            with self.assertRaises(RuntimeError):
                self.run_jobs([Job('sleep', (), (sleeper,), 1), Job('fail', (), (failure,), 1)])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_timeout(self):
        with self.assertRaises(TimeoutError):
            self.run_jobs([Job('slow', (), (command('import time; time.sleep(30)'),), 1)], timeout=.03)

    def test_ready_parent_does_not_wait_for_unrelated_node(self):
        jobs = [Job('left', (), (command('pass'),), 1),
                Job('right', (), (command('pass'),), 1),
                Job('unrelated', (), (command('import time; time.sleep(.3)'),), 1),
                Job('parent', ('left', 'right'), (command('pass'),), 1, 1)]
        report = self.run_jobs(jobs, workers=3, memory=3)
        self.assertLess(report['jobs']['parent']['completed_ns'], report['jobs']['unrelated']['completed_ns'])

    def test_admission_failure_blocks_dependents(self):
        def reject(job, logs):
            raise RuntimeError('artifact mismatch')
        with self.assertRaisesRegex(RuntimeError, 'artifact mismatch'):
            self.run_jobs([Job('child', (), (command('pass'),), 1),
                           Job('parent', ('child',), (command('pass'),), 1)], admit=reject)


if __name__ == '__main__':
    unittest.main()
