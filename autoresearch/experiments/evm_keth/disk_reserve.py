"""Fail closed before generated traces or backing files exhaust their volume."""
from pathlib import Path
import shutil
import time


class DiskReserve:
    def __init__(self, directory: Path, minimum_free_bytes: int):
        if minimum_free_bytes <= 0:
            raise ValueError('positive disk reserve required')
        self.directory = directory.resolve()
        self.minimum = minimum_free_bytes
        self.lowest = None
        self.observations = 0
        self.next_check_ns = 0

    def check(self):
        now = time.monotonic_ns()
        if now < self.next_check_ns:
            return None
        self.next_check_ns = now + 250_000_000
        try:
            free = shutil.disk_usage(self.directory).free
        except OSError:
            return 'free-disk monitoring became unavailable'
        self.observations += 1
        self.lowest = free if self.lowest is None else min(self.lowest, free)
        if free < self.minimum:
            return 'free disk fell below the explicit reserve'
        return None

    def record(self):
        return dict(path=str(self.directory), minimum_free_bytes=self.minimum,
                    lowest_observed_free_bytes=self.lowest, observations=self.observations)
