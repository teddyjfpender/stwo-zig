import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from recursive_proof_scheduler import Job, execute
from recursive_proof_worker_pool import ProducerPool

# Exercises the real pipe transport, process lifetime, request manifests and DAG
# admission without requiring a compiler or device.
WORKER = r'''
import hashlib,json,os,pathlib,sys,time
count=0
request=dict(path=sys.argv[-2],sha256=sys.argv[-1])
while True:
    data=pathlib.Path(request['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest()==request['sha256']
    args=json.loads(data)['requests'][0]
    mode,output=args[1:3]
    pathlib.Path(output+'.pid').write_text(str(os.getpid()))
    if mode=='sleep': time.sleep(30)
    if mode=='fail':
        while not pathlib.Path(args[3]).exists(): time.sleep(.01)
        raise SystemExit(9)
    if mode=='broken':
        print('{}',flush=True)
    else:
        pathlib.Path(output).write_text(str(os.getpid()))
        count+=1
        print(json.dumps(dict(endpoint='detached_parent_worker_candidate',requests=count)),flush=True)
    line=sys.stdin.readline()
    if not line: break
    request=json.loads(line)
if mode=='bad-shutdown': raise SystemExit(9)
'''


class WorkerPoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = self.root / 'worker.py'
        self.worker.write_text(WORKER)
        self.report = {}

    def job(self, name, dependencies=(), mode='ok', extra=(), verify_fail=False):
        artifact = self.root / name
        producer = (sys.executable, str(self.worker), '--profile', mode, str(artifact), *extra)
        verifier = (sys.executable, '-c',
                    f'from pathlib import Path; assert Path({str(artifact)!r}).is_file(); '
                    f'raise SystemExit({int(verify_fail)})')
        return Job(name, dependencies, (producer, verifier), 1)

    def run_jobs(self, jobs, capacity=2, budget=2, timeout=3, admit=lambda j, p: None):
        pool = ProducerPool(self.root / 'workers', capacity)
        try:
            execute(jobs, self.root / 'logs', workers=capacity, memory_bytes=budget,
                    timeout=timeout, env=dict(os.environ), admit=admit,
                    report=self.report, producer_pool=pool)
        finally:
            pool.close(failed=True)

    def assert_reaped(self):
        for path in self.root.glob('*.pid'):
            with self.assertRaises(ProcessLookupError):
                os.kill(int(path.read_text()), 0)

    def test_reuses_process_and_waits_for_independent_admission(self):
        accepted = []
        def admit(job, logs):
            self.assertEqual(len(logs), 2)
            if job.name == 'parent':
                self.assertEqual(set(accepted), {'a', 'b'})
            accepted.append(job.name)
        self.run_jobs([self.job('a'), self.job('b'), self.job('parent', ('a', 'b'))], admit=admit)
        self.assertTrue(self.report['passed'])
        self.assertEqual(self.report['resident_worker_reservation_bytes'], 2)
        pids = {p.read_text() for p in self.root.glob('*.pid')}
        self.assertEqual(len(pids), 2)
        responses = [json.loads(p.read_text()) for p in (self.root/'logs').glob('*-0.log')]
        self.assertEqual(sorted(r['requests'] for r in responses), [1, 1, 2])
        self.assert_reaped()

    def test_verifier_failure_does_not_release_parent(self):
        accepted = []
        with self.assertRaises(RuntimeError):
            self.run_jobs([self.job('a', verify_fail=True), self.job('parent', ('a',))],
                          admit=lambda j, p: accepted.append(j.name))
        self.assertFalse((self.root/'parent').exists())
        self.assertEqual(accepted, [])
        self.assert_reaped()

    def test_transport_failure_kills_other_busy_worker(self):
        with self.assertRaises(RuntimeError):
            self.run_jobs([self.job('a', mode='sleep'),
                           self.job('b', mode='fail', extra=(str(self.root/'a.pid'),))])
        self.assert_reaped()

    def test_timeout_reaps_blocked_reader(self):
        with self.assertRaises(TimeoutError):
            self.run_jobs([self.job('a', mode='sleep')], timeout=.2)
        self.assert_reaped()

    def test_malformed_response_fails_closed(self):
        with self.assertRaises(RuntimeError):
            self.run_jobs([self.job('a', mode='broken')])
        self.assert_reaped()

    def test_resident_memory_cannot_be_reclaimed_from_idle_workers(self):
        with self.assertRaises(ValueError):
            self.run_jobs([self.job('a')], budget=1)
        self.assertFalse((self.root/'a.pid').exists())

    def test_shutdown_failure_invalidates_report(self):
        with self.assertRaises(RuntimeError):
            self.run_jobs([self.job('a', mode='bad-shutdown')])
        self.assertFalse(self.report['passed'])
        self.assert_reaped()


if __name__ == '__main__':
    unittest.main()
