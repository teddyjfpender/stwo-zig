"""Persistent producer transport for the bounded proof DAG executor.

One pinned manifest per request; no retries. Each resident process owns a single
workspace. Cancellation kills process groups, unblocks readers and joins threads.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading


def kill(process):
    # Reap an already exited leader before signalling its remaining group.
    process.poll()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class RequestProcess:
    def __init__(self, future, pool):
        self.future, self.pool = future, pool

    def poll(self):
        if not self.future.done():
            return None
        # Propagate transport errors; they must never look like successful EOF.
        self.future.result()
        return 0

    def wait(self):
        return self.future.result()

    def cancel_group(self):
        self.pool.close(failed=True)


class ProducerPool:
    def __init__(self, directory: Path, capacity: int):
        if capacity < 1:
            raise ValueError('worker capacity must be positive')
        directory.mkdir(parents=True, exist_ok=False)
        self.directory, self.capacity = directory, capacity
        self.executor = ThreadPoolExecutor(max_workers=capacity)
        self.lock = threading.Lock()
        self.slots = [dict(index=i, process=None, busy=False, requests=0) for i in range(capacity)]
        self.closed = False

    def launch(self, argv, log, env):
        pos = argv.index('--profile')
        prefix = tuple(argv[:pos])
        with self.lock:
            if self.closed:
                raise RuntimeError('producer pool is closed')
            slot = next((s for s in self.slots if not s['busy']), None)
            if slot is None:
                raise RuntimeError('no idle producer slot')
            if slot['process'] is not None and (slot['prefix'] != prefix or slot['env'] != env):
                raise ValueError('worker runtime arguments or environment changed')
            slot['busy'] = True
        future = self.executor.submit(self._request, slot, prefix, argv[pos:], log, env)
        return RequestProcess(future, self)

    def _request(self, slot, prefix, argv, log, env):
        try:
            manifest = log.with_suffix('.request.json')
            payload = dict(version=1, session_byte_budget=64 << 20,
                           pcs_plan_byte_budget=256 << 20,
                           retained_scratch_byte_limit=256 << 20, requests=[list(argv)])
            data = (json.dumps(payload) + '\n').encode()
            manifest.write_bytes(data)
            pin = hashlib.sha256(data).hexdigest()
            with self.lock:
                if self.closed:
                    raise RuntimeError('producer pool cancelled')
                process = slot['process']
                if process is None:
                    index = slot['index']
                    with (self.directory / f'worker-{index}.log').open('xb') as stream:
                        process = subprocess.Popen([*prefix, '--worker', str(manifest), pin],
                            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=stream, start_new_session=True)
                    slot.update(process=process, prefix=prefix, env=dict(env))
                else:
                    if process.poll() is not None:
                        raise RuntimeError('persistent producer exited between requests')
                    message = (json.dumps(dict(path=str(manifest), sha256=pin)) + '\n').encode()
                    if len(message) > 8192:
                        raise ValueError('worker request framing too large')
                    process.stdin.write(message)
                    process.stdin.flush()
            # Bounded response, and killing the process on failure/timeout unblocks
            # this reader. stderr never shares the response pipe.
            response = process.stdout.readline((1 << 20) + 1)
            log.write_bytes(response)
            if len(response) > 1 << 20 or not response.endswith(b'\n'):
                raise RuntimeError('missing or oversized worker response')
            record = json.loads(response)
            slot['requests'] += 1
            if (record.get('endpoint') != 'detached_parent_worker_candidate'
                    or record.get('requests') != slot['requests']):
                raise RuntimeError('worker response sequence mismatch')
        finally:
            with self.lock:
                slot['busy'] = False

    def close(self, *, failed=False):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            processes = [s['process'] for s in self.slots if s['process'] is not None]
        error = None
        for process in processes:
            if failed:
                kill(process)
                continue
            try:
                process.stdin.close()
                if process.wait(timeout=10) != 0:
                    raise RuntimeError('persistent worker failed on shutdown')
            except BaseException as caught:
                kill(process)
                error = caught
        self.executor.shutdown(wait=True, cancel_futures=True)
        for process in processes:
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()
        if error is not None:
            raise error

    def pids(self):
        with self.lock:
            return [s['process'].pid for s in self.slots
                    if s['process'] is not None and s['process'].poll() is None]
