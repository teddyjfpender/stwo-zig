"""Bounded process DAG executor; a node completes only after all phases and admission.

Memory reservations are caller estimates, not an OS-enforced RSS limit. Commands
must be trusted/admitted by the caller. No shell, ambient lock bypass or retries.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Callable


@dataclass(frozen=True)
class Job:
    name: str
    dependencies: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]
    memory_bytes: int
    priority: int = 0


def execute(jobs: list[Job], output: Path, *, workers: int, memory_bytes: int,
            timeout: float, env: dict[str, str], admit: Callable[[Job, list[Path]], None],
            report: dict, producer_pool=None, sample_rss=False) -> None:
    """Run ready jobs, retaining failure evidence and reaping every owned process."""
    names = {job.name for job in jobs}
    if len(names) != len(jobs) or workers < 1 or memory_bytes < 1 or timeout <= 0:
        raise ValueError('invalid scheduler limits or duplicate jobs')
    for job in jobs:
        if (not job.name or Path(job.name).name != job.name or job.name in ('.', '..')
                or not job.commands or any(not command for command in job.commands)
                or not 0 < job.memory_bytes <= memory_bytes
                or not set(job.dependencies) <= names):
            raise ValueError(f'invalid or unschedulable job: {job.name}')
    reachable: set[str] = set()
    while True:
        added = {j.name for j in jobs if set(j.dependencies) <= reachable} - reachable
        if not added:
            break
        reachable |= added
    if reachable != names:
        raise ValueError('cyclic dependencies')
    if producer_pool is not None:
        footprint = max((j.memory_bytes for j in jobs), default=0)
        if producer_pool.capacity > workers or producer_pool.capacity * footprint > memory_bytes:
            raise ValueError('resident producer pool exceeds worker or memory budget')
        workers = producer_pool.capacity
    output.mkdir(parents=True, exist_ok=False)
    report.update(passed=False, workers=workers, memory_budget_bytes=memory_bytes,
                  memory_scope='caller reservations; not measured peak RSS', jobs={},
                  maximum_reserved_bytes=0, maximum_active_jobs=0)
    if producer_pool is not None:
        report['resident_worker_reservation_bytes'] = producer_pool.capacity * footprint
    pending = sorted(jobs, key=lambda j: (-j.priority, j.name))
    complete: set[str] = set()
    active: dict[str, dict] = {}
    started = time.monotonic_ns()
    next_sample = started
    if sample_rss:
        report.update(rss_samples=[], peak_sampled_rss_bytes=0,
                      rss_scope='sum of resident worker and active phase process RSS; excludes device allocations and descendants')

    def launch(state: dict) -> None:
        job, phase = state['job'], state['phase']
        log = output / f'{job.name}-{phase}.log'
        if producer_pool is not None and phase == 0:
            process = producer_pool.launch(job.commands[phase], log, env)
        else:
            with log.open('xb') as stream:
                process = subprocess.Popen(job.commands[phase], env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
        state.update(process=process, launched=time.monotonic_ns())
        state['logs'].append(log)
        state['record']['phases'].append({'argv': list(job.commands[phase]),
                                         'log': str(log), 'started_ns': state['launched'] - started})

    try:
        while pending or active:
            if sample_rss and time.monotonic_ns() >= next_sample:
                pids = {s['process'].pid for s in active.values()
                        if hasattr(s.get('process'), 'pid') and s['process'].poll() is None}
                if producer_pool is not None:
                    pids.update(producer_pool.pids())
                if pids:
                    sample = subprocess.run(['ps', '-o', 'pid=,rss=', '-p', ','.join(map(str, sorted(pids)))],
                                            capture_output=True, text=True, timeout=2)
                    if sample.returncode not in (0, 1):
                        raise RuntimeError('RSS sampling failed')
                    values = {int(pid): int(kib) * 1024 for pid, kib in
                              (line.split() for line in sample.stdout.splitlines())}
                    total = sum(values.values())
                    report['rss_samples'].append(dict(elapsed_ns=time.monotonic_ns() - started,
                                                       process_bytes=values, total_bytes=total))
                    report['peak_sampled_rss_bytes'] = max(report['peak_sampled_rss_bytes'], total)
                next_sample = time.monotonic_ns() + 100_000_000
            for name, state in list(active.items()):
                process = state['process']
                code = process.poll()
                elapsed = (time.monotonic_ns() - state['launched']) / 1e9
                if code is None:
                    if elapsed > timeout:
                        raise TimeoutError(f'{name}: phase {state["phase"]} timed out')
                    continue
                state['record']['phases'][-1].update(exit_code=code, seconds=elapsed)
                if code:
                    raise RuntimeError(f'{name}: phase {state["phase"]} exited {code}')
                state['phase'] += 1
                if state['phase'] < len(state['job'].commands):
                    launch(state)
                else:
                    admit(state['job'], state['logs'])
                    state['record'].update(accepted=True, completed_ns=time.monotonic_ns() - started)
                    complete.add(name)
                    del active[name]
            reserved = sum(s['job'].memory_bytes for s in active.values())
            for job in pending[:]:
                if len(active) >= workers:
                    break
                if not set(job.dependencies) <= complete or reserved + job.memory_bytes > memory_bytes:
                    continue
                record = {'accepted': False, 'dependencies': list(job.dependencies),
                          'memory_bytes': job.memory_bytes, 'phases': []}
                report['jobs'][job.name] = record
                state = {'job': job, 'phase': 0, 'logs': [], 'record': record}
                active[job.name] = state
                launch(state)
                pending.remove(job)
                reserved += job.memory_bytes
            report['maximum_reserved_bytes'] = max(report['maximum_reserved_bytes'], reserved)
            report['maximum_active_jobs'] = max(report['maximum_active_jobs'], len(active))
            if pending or active:
                time.sleep(0.01)
        report['passed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        for state in active.values():
            process = state.get('process')
            if process is not None:
                if hasattr(process, 'cancel_group'):
                    process.cancel_group()
                    state['record']['cancelled'] = True
                    continue
                # Kill the owned group even if its leader has exited; descendants
                # must not outlive failure/cancellation of the proof transaction.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                state['record']['cancelled'] = True
        try:
            if producer_pool is not None:
                producer_pool.close(failed=not report['passed'])
        except BaseException as error:
            report.update(passed=False, error=f'{type(error).__name__}: {error}')
            raise
        finally:
            report['wall_ns'] = time.monotonic_ns() - started
