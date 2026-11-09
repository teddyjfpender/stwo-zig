#!/usr/bin/env python3
"""Reproduce the rejected SIMD diagonal experiment in an isolated temporary copy.

The workspace's production crypto sources are never edited. The compiled binary
interleaves original absent-hook SIMD with the temporary rotation candidate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE_INTERNAL = '    for (3..WIDTH) |i| state[i] = try ops.add(all, try ops.mul(state[i], try ops.constant(parameters.INTERNAL_DIAGONAL[i])));'
CANDIDATE_INTERNAL = """    if (comptime @hasDecl(@TypeOf(ops), "mulPow2")) {
        inline for (3..WIDTH) |i| {
            const diagonal = parameters.INTERNAL_DIAGONAL[i];
            comptime std.debug.assert(std.math.isPowerOfTwo(diagonal));
            state[i] = try ops.add(all, try ops.mulPow2(state[i], @ctz(diagonal)));
        }
    } else {
        // Keep the default source/circuit operation sequence unchanged.
        for (3..WIDTH) |i| state[i] = try ops.add(all, try ops.mul(state[i], try ops.constant(parameters.INTERNAL_DIAGONAL[i])));
    }"""
CANDIDATE_METHOD = """    /// Canonical M31 multiplication by 2^k is a rotation of 31 bits. A
    /// canonical input cannot rotate into the excluded all-ones encoding.
    pub inline fn mulPow2(_: @This(), value: V, comptime power: u5) !V {
        comptime std.debug.assert(power > 0 and power < 31);
        return ((value << @as(@Vector(4, u5), @splat(power))) & @as(V, @splat(F.Modulus))) | (value >> @as(@Vector(4, u5), @splat(31 - power)));
    }"""
CANDIDATE_EDGE_TEST = """test "Sponge4 power-of-two diagonal is canonical scalar exact for edges and random lanes" {
    var prng = std.Random.DefaultPrng.init(0x504f5745523331);
    const random = prng.random();
    const edges = [_]u32{ 0, 1, 2, 3, F.Modulus - 1, F.Modulus - 2, F.Modulus / 2, 0x40000000, 0xffff, 0x10000 };
    inline for (2..23) |power| {
        for (0..edges.len + 256) |round| {
            var values: [4]u32 = undefined;
            for (&values, 0..) |*value, lane| value.* = if (round < edges.len) edges[(round + lane) % edges.len] else random.uintLessThan(u32, F.Modulus);
            const result: [4]u32 = try Ops.mulPow2(.{}, @bitCast(values), power);
            for (values, result) |value, got| {
                try std.testing.expect(got < F.Modulus);
                try std.testing.expectEqual(F.M31.fromCanonical(value).mul(F.M31.fromCanonical(@as(u32, 1) << power)).v, got);
            }
        }
    }
}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', default=shutil.which('zig') or '/opt/homebrew/Cellar/zig@0.15/0.15.2/bin/zig')
    parser.add_argument('--groups', type=int, default=32768)
    parser.add_argument('--repeats', type=int, default=9)
    parser.add_argument('--mode', choices=['node18', 'leaf64', 'leaf128', 'balanced', 'permutation'])
    parser.add_argument('--parity-only', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if not 0 < args.groups <= 1 << 20 or not 3 <= args.repeats <= 31:
        parser.error('groups must be 1..2^20 and repeats 3..31')
    root = Path(__file__).resolve().parents[1]
    files = ['fields/m31.zig', 'crypto/poseidon2_m31_w24.zig', 'crypto/poseidon2_m31_w24_constants.zig',
             'crypto/poseidon2_m31_w24_vectors.zig', 'crypto/poseidon2_m31_sponge.zig',
             'crypto/poseidon2_m31_sponge4.zig', 'crypto/poseidon2_m31_sponge4_test.zig',
             'poseidon2_sponge4_test_root.zig']
    metrics = []
    with tempfile.TemporaryDirectory(prefix='stwo-p2-diagonal-') as directory:
        work = Path(directory)
        for relative in files:
            target = work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / 'src/core' / relative, target)
        shutil.copyfile(root / 'scripts/bench_poseidon2_diagonal_rotation_lib/benchmark.zig', work / 'poseidon2_sponge4_benchmark.zig')
        permutation = work / 'crypto/poseidon2_m31_w24.zig'
        original = permutation.read_text()
        if original.count(BASE_INTERNAL) != 1 or '"mulPow2"' in original:
            raise RuntimeError('Baseline permutation changed; review the experiment before rebuilding')
        permutation.write_text(original.replace(BASE_INTERNAL, CANDIDATE_INTERNAL))
        sponge = work / 'crypto/poseidon2_m31_sponge4.zig'
        original_sponge = sponge.read_text()
        if 'fn mulPow2' in original_sponge or original_sponge.count('const Ops = struct {') != 1:
            raise RuntimeError('Baseline SIMD Ops changed; review the experiment before rebuilding')
        candidate = original_sponge.replace('const Ops = struct {', 'pub const DIAGONAL_ROTATION_EXPERIMENT = true;\nconst Ops = struct {\n' + CANDIDATE_METHOD)
        sponge.write_text(candidate + '\n' + CANDIDATE_EDGE_TEST)
        tests = subprocess.run([args.zig, 'test', '-OReleaseSafe', str(work / 'poseidon2_sponge4_test_root.zig')], text=True, capture_output=True)
        print(tests.stderr, end='')
        if tests.returncode:
            raise RuntimeError('Candidate parity failed')
        if not args.parity_only:
            binary = work / 'benchmark'
            subprocess.run([args.zig, 'build-exe', '-OReleaseFast', str(work / 'poseidon2_sponge4_benchmark.zig'), '-femit-bin=' + str(binary)], check=True)
            command = [str(binary), str(args.groups), str(args.repeats)]
            if args.mode:
                command.append(args.mode)
            measured = subprocess.run(command, text=True, capture_output=True, check=True)
            print(measured.stderr, end='')
            for line in measured.stderr.splitlines():
                if line.startswith('P2_HASH_AB '):
                    fields = dict(part.split('=', 1) for part in line.split()[1:])
                    metrics.append({key: value if key == 'mode' else float(value) if key == 'speedup' else int(value) for key, value in fields.items()})
        report = {'schema': 'p2-diagonal-rotation-experiment/v1', 'machine': platform.machine(),
                  'zig': subprocess.check_output([args.zig, 'version'], text=True).strip(),
                  'production_adopted': False, 'production_sources_modified': False,
                  'parity_passed': True, 'default_ops': 4040,
                  'default_ir_sha256': '8240740eb07c131ea9f8c41442be88c500367839c4afe02da46ba702f1615108',
                  'baseline_permutation_sha256': hashlib.sha256(original.encode()).hexdigest(),
                  'temporary_candidate_sha256': hashlib.sha256(permutation.read_bytes()).hexdigest(),
                  'metrics': metrics, 'quiet_machine': 'caller must establish separately'}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
