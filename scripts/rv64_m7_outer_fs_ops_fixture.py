#!/usr/bin/env python3
"""Scoped GPU parity/custody gate for outer FS lookup parameters; no speed claim."""
import argparse
import ctypes as c
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', required=True)
    p.add_argument('--addon', required=True)
    p.add_argument('--reference', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--gpu-lock', default='/workspace/m3/locks/gpu.lock')
    a = p.parse_args()
    os.environ['STWO_RV64_DEVICE_ARENA'] = '0'
    corpus = Path(a.reference).read_bytes()
    assert len(corpus) == 84 * 72 * 4
    rows = [struct.unpack('<72I', corpus[i:i + 288]) for i in range(0, len(corpus), 288)]
    receipt = dict(schema='rv64-m7-outer-fs-lookup-fixture/v1',
                   scope='lookup parameter derivation only; not full device FS or request qualification',
                   base_sha256=sha(a.base), addon_sha256=sha(a.addon),
                   reference_sha256=sha(a.reference), tests=[])
    with open(a.gpu_lock, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        base = c.CDLL(a.base, mode=c.RTLD_GLOBAL)
        addon = c.CDLL(a.addon)

        def fn(lib, name, args):
            f = getattr(lib, name)
            f.argtypes, f.restype = args, c.c_int
            return f

        ptr, sz, u32 = c.c_void_p, c.c_size_t, c.c_uint32
        create = fn(base, 'stwo_exec_context_create_options', [ptr, c.POINTER(ptr)])
        destroy = fn(base, 'stwo_exec_context_destroy', [ptr])
        alloc = fn(base, 'stwo_exec_context_alloc_u32', [ptr, sz, c.POINTER(ptr)])
        free = fn(base, 'stwo_exec_context_free_u32', [ptr, ptr])
        sync = fn(base, 'stwo_exec_context_sync', [ptr])
        h2d = fn(base, 'stwo_exec_context_memcpy_h2d_async', [ptr, ptr, ptr, sz])
        d2h = fn(base, 'stwo_exec_context_memcpy_d2h_async', [ptr, ptr, ptr, sz])
        op = fn(addon, 'stwo_rv64_outer_fs_lookup_params_on', [ptr, u32, ptr, ptr, ptr])

        def ok(code):
            assert code == 0, code

        def check(name, condition):
            assert condition, name
            receipt['tests'].append(name)

        for device in (0, 1):
            contexts, leases = [], []
            try:
                for _ in range(2):
                    context = ptr()
                    options = (u32 * 4)(1, device, 1, 0)
                    ok(create(options, c.byref(context)))
                    contexts.append(context)
                ctx, foreign = contexts

                def new(n, owner=None):
                    owner = ctx if owner is None else owner
                    memory = ptr()
                    ok(alloc(owner, n, c.byref(memory)))
                    leases.append((owner, memory))
                    return memory

                def upload(memory, words):
                    host = (u32 * len(words))(*words)
                    ok(h2d(ctx, memory, host, len(words) * 4))
                    # Keep pageable host memory alive through this transfer.
                    ok(sync(ctx))

                def download(memory, n):
                    host = (u32 * n)()
                    ok(d2h(ctx, host, memory, n * 4))
                    ok(sync(ctx))
                    return list(host)

                inputs, output, status = new(16), new(56), new(1)
                for index, row in enumerate(rows):
                    upload(inputs, row[:16])
                    upload(status, [4])
                    ok(op(ctx, 0, inputs, output, status))
                    check(f'device{device}/core-parity-{index}',
                          download(output, 56) == list(row[16:]) and download(status, 1) == [4])
                for index in (0, 7, 8, 15):
                    for bad in (2147483647, 4294967295):
                        words = list(rows[-1][:16])
                        words[index] = bad
                        upload(inputs, words)
                        upload(output, [0x5a5a5a5a] * 56)
                        upload(status, [4])
                        ok(op(ctx, 0, inputs, output, status))
                        check(f'device{device}/canonical-{index}-{bad}',
                              download(status, 1) == [5] and
                              download(output, 56) == [0x5a5a5a5a] * 56)
                large, short_in, short_out = new(80), new(15), new(55)
                other = new(16, foreign)
                host = (u32 * 16)()
                retired = new(16)
                ok(free(ctx, retired))
                leases.pop()
                for name, args in [
                    ('null-input', (ctx, 0, None, output, status)),
                    ('short-input', (ctx, 0, short_in, output, status)),
                    ('short-output', (ctx, 0, inputs, short_out, status)),
                    ('foreign-context', (ctx, 0, other, output, status)),
                    ('host-input', (ctx, 0, c.cast(host, ptr), output, status)),
                    ('retired-input', (ctx, 0, retired, output, status)),
                    ('input-output-overlap', (ctx, 0, large, large, status)),
                    ('status-output-overlap', (ctx, 0, inputs, output, output)),
                    ('status-input-overlap', (ctx, 0, inputs, output, inputs)),
                    ('unaligned-input', (ctx, 0, ptr(inputs.value + 1), output, status)),
                    ('invalid-lane', (ctx, 1, inputs, output, status)),
                ]:
                    check(f'device{device}/{name}', op(*args) != 0)
                ok(sync(ctx))
            finally:
                for owner, memory in reversed(leases):
                    ok(free(owner, memory))
                for context in reversed(contexts):
                    ok(destroy(context))
    receipt.update(passed=True, checks=len(receipt['tests']))
    Path(a.out).write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({k: v for k, v in receipt.items() if k != 'tests'}), flush=True)


if __name__ == '__main__':
    main()
