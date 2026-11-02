"""Explicit, platform-aware resource policy for benchmark processes."""
from __future__ import annotations

from contextlib import contextmanager
import resource
import sys


def default_address_space_gib() -> int:
    # Darwin exposes RLIMIT_AS but rejects practical limits with EINVAL.
    return 8 if sys.platform.startswith('linux') else 0


@contextmanager
def address_space_limit(gib: int | float):
    if gib < 0:
        raise ValueError('address-space limit must be nonnegative')
    policy = {'requested_gib': gib, 'enforced': False,
              'scope': 'per-process virtual address space; inherited by children',
              'platform': sys.platform}
    if not gib:
        yield policy
        return
    if not sys.platform.startswith('linux'):
        raise ValueError('RLIMIT_AS enforcement is supported only on Linux; use '
                         '--max-address-space-gib 0 to explicitly run without it')
    previous = resource.getrlimit(resource.RLIMIT_AS)
    requested = int(gib * (1 << 30))
    if previous[0] != resource.RLIM_INFINITY:
        requested = min(requested, previous[0])
    resource.setrlimit(resource.RLIMIT_AS, (requested, previous[1]))
    policy.update(enforced=True, effective_bytes=requested)
    try:
        yield policy
    finally:
        resource.setrlimit(resource.RLIMIT_AS, previous)
