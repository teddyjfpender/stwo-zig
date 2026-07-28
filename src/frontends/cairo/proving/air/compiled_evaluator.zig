//! Register-resident compiled evaluation of captured Cairo AIR programs.
//!
//! The template interpreter (`simd_evaluator.zig`) holds every intermediate
//! value in a heap-allocated register file — `max_base_regs` PackedM31 plus
//! `max_ext_regs` PackedQm31, 31.5 KB for the dominant arithmetic-2m
//! component — so each interpreted instruction is a load-operands / compute /
//! store-result round trip against L1D. A compiled evaluator emits the same
//! arithmetic as straight-line code whose values are ordinary locals, so
//! LLVM's register allocator decides what lives in a NEON register and what
//! spills, and the majority of short-lived values never touch memory.
//!
//! Admission is **structural**, never nominal. A generated evaluator is used
//! only when the captured program's own instruction encoding hashes to the
//! encoding the evaluator was generated from: `Program.semantic_hash` is
//! checked first as a cheap filter, then the canonical encoding of every
//! constant, instruction and constraint root is re-hashed with SHA-256 and
//! compared against the digest baked into the generated module. Nothing
//! inspects a workload name, an input path, a proof digest or a component
//! label. Any program that does not match runs on the interpreter.
//!
//! Correctness contract: for an admitted program the compiled body computes
//! the same values, from the same inputs, with the same primitives in the same
//! operand order, and accumulates rows in the same ascending order. Proof
//! bytes are therefore identical, and a mismatch fails closed — the verifier
//! recomputes the composition polynomial through the interpreter path at the
//! OODS point.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const utils = @import("stwo_core").utils;
const eval = @import("../../witness/eval_program.zig");
const read_plan = @import("read_plan.zig");
const simd = @import("simd_evaluator.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = simd.PackedM31;
const PackedQm31 = simd.PackedQm31;
const lane_count = simd.lane_count;

/// Every generated evaluator in the product, in admission order.
pub const modules = [_]type{
    @import("generated/add_opcode_small.zig"),
};

/// Runs `program` on a generated evaluator when one matches it structurally.
/// Returns `false` when no evaluator matches, leaving the caller to run the
/// interpreter; returns `true` once the range has been fully evaluated.
pub fn tryEvaluatePartRange(
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: simd.Input,
    output: anytype,
    row_start: usize,
    row_end: usize,
) !bool {
    inline for (modules) |module| {
        if (matches(module, program, input)) {
            try evaluateWith(
                module,
                allocator,
                program,
                input,
                output,
                row_start,
                row_end,
            );
            return true;
        }
    }
    return false;
}

/// Cheap shape filter, then the collision-resistant structural digest. The
/// shape checks are what make the digest meaningful: they pin the register
/// counts, parameter count and constraint count the generated body indexes
/// with compile-time constants.
fn matches(
    comptime module: type,
    program: eval.Program,
    input: simd.Input,
) bool {
    if (program.header.semantic_hash != module.semantic_hash) return false;
    if (program.header.max_base_regs != module.max_base_regs or
        program.header.max_ext_regs != module.max_ext_regs or
        program.header.n_base_params != 0 or
        program.header.n_ext_params != module.n_ext_params or
        program.header.n_constraints != module.n_constraints or
        program.base_insts.len != module.n_base_insts or
        program.ext_insts.len != module.n_ext_insts or
        program.constraint_roots.len != module.n_constraints)
        return false;
    if (input.extension_parameters.len != module.n_ext_params) return false;
    var digest: [32]u8 = undefined;
    structuralDigest(program, &digest);
    return std.mem.eql(u8, &digest, &module.structural_sha256);
}

/// SHA-256 over the canonical little-endian encoding of the program's
/// semantic payload: base constants, extension constants, base instructions,
/// extension instructions, constraint roots. Byte-for-byte the payload
/// `Program.semanticHash` folds over, so a match pins the whole program.
fn structuralDigest(program: eval.Program, out: *[32]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var scratch: [20]u8 = undefined;
    for (program.base_consts) |value| {
        std.mem.writeInt(u32, scratch[0..4], value, .little);
        hasher.update(scratch[0..4]);
    }
    for (program.ext_consts) |value| {
        for (value, 0..) |coordinate, index| {
            std.mem.writeInt(u32, scratch[index * 4 ..][0..4], coordinate, .little);
        }
        hasher.update(scratch[0..16]);
    }
    for (program.base_insts) |instruction| {
        scratch[0] = @intFromEnum(instruction.op);
        scratch[1] = instruction.interaction;
        std.mem.writeInt(u16, scratch[2..4], instruction.dst, .little);
        std.mem.writeInt(u32, scratch[4..8], instruction.a, .little);
        std.mem.writeInt(u32, scratch[8..12], instruction.b, .little);
        std.mem.writeInt(i32, scratch[12..16], instruction.imm, .little);
        hasher.update(scratch[0..16]);
    }
    for (program.ext_insts) |instruction| {
        scratch[0] = @intFromEnum(instruction.op);
        scratch[1] = 0;
        std.mem.writeInt(u16, scratch[2..4], instruction.dst, .little);
        std.mem.writeInt(u32, scratch[4..8], instruction.a, .little);
        std.mem.writeInt(u32, scratch[8..12], instruction.b, .little);
        std.mem.writeInt(u32, scratch[12..16], instruction.c, .little);
        std.mem.writeInt(u32, scratch[16..20], instruction.d, .little);
        hasher.update(scratch[0..20]);
    }
    for (program.constraint_roots) |root| {
        std.mem.writeInt(u32, scratch[0..4], root, .little);
        hasher.update(scratch[0..4]);
    }
    hasher.final(out);
}

/// The row loop. Everything outside the generated body — the domain checks,
/// the read-plan resolution, the per-group offset map, the mask gather, the
/// denominator and the scatter — is the interpreter's own code path, so the
/// only thing that differs between the two arms is how the arithmetic runs.
fn evaluateWith(
    comptime module: type,
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: simd.Input,
    output: anytype,
    row_start: usize,
    row_end: usize,
) !void {
    if (program.header.domain_log_size != input.trace_log_size or
        input.trace_log_size > input.evaluation_log_size or
        input.constraint_base + module.n_constraints > input.random_coefficients.len)
        return error.InvalidEvaluationInput;
    const row_count = checkedPow2(input.evaluation_log_size) catch
        return error.InvalidEvaluationInput;
    const denominator_count = checkedPow2(
        input.evaluation_log_size - input.trace_log_size,
    ) catch return error.InvalidEvaluationInput;
    if (row_count % lane_count != 0 or
        input.denominator_inverses.len != denominator_count or
        row_start > row_end or
        row_end > row_count or
        row_start % lane_count != 0 or
        row_end % lane_count != 0)
        return error.InvalidEvaluationInput;

    var plan = try read_plan.build(
        simd.ResolvedColumn,
        allocator,
        program,
        input.trace.context,
        input.trace.resolve,
    );
    defer plan.deinit(allocator);
    if (plan.sites.len != module.n_reads) return error.InvalidEvaluationInput;
    const positions = try allocator.alloc([lane_count]usize, plan.offsets.len);
    defer allocator.free(positions);

    // Row-invariant splats, hoisted once per range. The interpreter re-splats
    // these inside every group; the values are identical.
    var parameters: [module.n_ext_params]PackedQm31 = undefined;
    for (&parameters, input.extension_parameters) |*slot, value| {
        slot.* = PackedQm31.splat(value);
    }
    var coefficients: [module.n_constraints]PackedQm31 = undefined;
    for (&coefficients, 0..) |*slot, index| {
        slot.* = PackedQm31.splat(
            input.random_coefficients[input.constraint_base + index],
        );
    }

    var reads: [module.n_reads]PackedM31 = undefined;
    var row = row_start;
    while (row < row_end) : (row += lane_count) {
        for (plan.offsets, positions) |offset, *mapped| {
            inline for (0..lane_count) |lane| {
                mapped[lane] = if (offset == 0)
                    row + lane
                else
                    utils.offsetBitReversedCircleDomainIndex(
                        row + lane,
                        input.trace_log_size,
                        input.evaluation_log_size,
                        offset,
                    );
            }
        }
        for (plan.sites, &reads) |site, *slot| {
            const mapped = positions[site.offset_slot];
            inline for (0..lane_count) |lane| {
                const position = mapped[lane];
                slot[lane] = site.column.values[
                    ((position >> site.column.shift_amt) << 1) +
                        (position & 1)
                ].toU32();
            }
        }
        var evaluation = module.evalGroup(&reads, &parameters, &coefficients);
        var denominator: PackedM31 = undefined;
        inline for (0..lane_count) |lane| {
            denominator[lane] = input.denominator_inverses[
                (row + lane) >> @intCast(input.trace_log_size)
            ];
        }
        evaluation = PackedQm31.mulBase(evaluation, denominator);
        inline for (0..lane_count) |lane| {
            output.accumulate(row + lane, evaluation.lane(lane));
        }
    }
}

fn checkedPow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "compiled evaluator: the generated module's digest matches the shipped template" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        "vectors/cairo/official/all_builtins_canonical_small.air_programs_v1.bin",
        16 * 1024 * 1024,
    );
    defer allocator.free(bytes);
    const composition = @import("../../witness/composition_bundle.zig");
    var bundle = try composition.Bundle.parse(allocator, bytes);
    defer bundle.deinit();

    inline for (modules) |module| {
        var found = false;
        for (bundle.components) |component| {
            for (component.parts) |part| {
                if (part.program.header.semantic_hash != module.semantic_hash)
                    continue;
                found = true;
                var digest: [32]u8 = undefined;
                structuralDigest(part.program, &digest);
                try std.testing.expectEqualSlices(
                    u8,
                    &module.structural_sha256,
                    &digest,
                );
                try std.testing.expectEqual(
                    @as(usize, module.n_base_insts),
                    part.program.base_insts.len,
                );
                try std.testing.expectEqual(
                    @as(usize, module.n_ext_insts),
                    part.program.ext_insts.len,
                );
            }
        }
        try std.testing.expect(found);
    }
}
