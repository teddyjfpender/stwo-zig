//! Exact public Word16 span/fold reference for a future *in-circuit* verifier.
//! A FoldedSpan contains host-visible public values and LogUp claims; those
//! are NOT proof of execution unless the actual native STARKs are first
//! independently verified. Only verifyNativeAndFold exposes an accepting
//! native multi-proof boundary. No recursive prover, recursive verifier,
//! compact root or 128-bit protocol is implemented here.
const std = @import("std");
const G = @import("../protocol.zig");
const Q = G.Q;
const P = @import("protocol.zig");
const R = @import("roster.zig");
const E = @import("execution.zig");
const Cpu = E.CpuEncoded;
const Truth = E.TruthEncoded;
pub const Digest = [32]u8;

pub const FoldedSpan = struct {
    program: Digest,
    image: Digest,
    first_epoch: u32,
    end_epoch_exclusive: u32,
    first_step: u64,
    steps: u64,
    cpu_count: u32,
    first_pc: u64,
    final_pc: u64,
    first_registers: [32]u64,
    final_registers: [32]u64,
    ram: Q,
    keccak_io: Q,
    secp_wire: Q,
};
pub const NativeRoot = struct {
    span: FoldedSpan,
    truth_proofs: u32,
    /// Only the native E.verify route authenticates this statement today.
    pub const recursively_verified = false;
    pub const whole_protocol_128_qualified = false;
};

/// Pure public-statement mapping, not a native proof verifier. This is the
/// exact data a future in-circuit leaf must connect to a verified child STARK.
pub fn fromPublicCpu(expected: P.Expected, encoded: Cpu, ordinal: usize, first_step: u64) !FoldedSpan {
    if (ordinal >= 65535 or encoded.request.base.epoch != ordinal + 1 or
        encoded.request.base.memory.epoch != ordinal + 1)
        return error.InvalidWord16SpanEpoch;
    const cpu = encoded.request.base.cpu;
    if (cpu.steps == 0 or cpu.steps > expected.admission.max_prefix_steps)
        return error.InvalidWord16SpanSteps;
    const end = std.math.add(u64, first_step, cpu.steps) catch return error.Word16SpanOverflow;
    if (end > expected.total_steps) return error.InvalidWord16SpanSteps;
    return .{
        .program = expected.program_identity, .image = expected.admission.image_identity,
        .first_epoch = @intCast(ordinal + 1), .end_epoch_exclusive = @intCast(ordinal + 2),
        .first_step = first_step, .steps = cpu.steps, .cpu_count = 1,
        .first_pc = cpu.initial_pc, .final_pc = cpu.final_pc,
        .first_registers = cpu.initial_registers, .final_registers = cpu.final_registers,
        .ram = encoded.claims.ram(),
        .keccak_io = encoded.claims.extras[0].truth,
        .secp_wire = encoded.claims.extras[1].truth.add(encoded.claims.extras[2].truth),
    };
}

/// Structural fold: every term must eventually be enforced *inside the
/// parent circuit* after the child proofs are verified in that circuit.
/// Claim addition in this Zig function alone provides no soundness.
pub fn fold(left: FoldedSpan, right: FoldedSpan) !FoldedSpan {
    if (!std.mem.eql(u8, &left.program, &right.program) or
        !std.mem.eql(u8, &left.image, &right.image))
        return error.Word16FoldIdentityMismatch;
    if (left.end_epoch_exclusive != right.first_epoch or
        (std.math.add(u64, left.first_step, left.steps) catch return error.Word16SpanOverflow) != right.first_step or
        left.final_pc != right.first_pc or
        !std.mem.eql(u64, &left.final_registers, &right.first_registers))
        return error.Word16FoldNonadjacent;
    const steps = std.math.add(u64, left.steps, right.steps) catch return error.Word16SpanOverflow;
    const count = std.math.add(u32, left.cpu_count, right.cpu_count) catch return error.Word16SpanOverflow;
    return .{ .program = left.program, .image = left.image,
        .first_epoch = left.first_epoch, .end_epoch_exclusive = right.end_epoch_exclusive,
        .first_step = left.first_step, .steps = steps, .cpu_count = count,
        .first_pc = left.first_pc, .final_pc = right.final_pc,
        .first_registers = left.first_registers, .final_registers = right.final_registers,
        .ram = left.ram.add(right.ram),
        .keccak_io = left.keccak_io.add(right.keccak_io),
        .secp_wire = left.secp_wire.add(right.secp_wire) };
}
/// Pure final statement conditions. It assumes truth public claims have already
/// been authenticated against their actual separately verified STARKs.
pub fn closePublic(expected: P.Expected, span: FoldedSpan, truths: []const R.Truth, encoded: []const Truth) !NativeRoot {
    if (!std.mem.eql(u8, &span.program, &expected.program_identity) or
        !std.mem.eql(u8, &span.image, &expected.admission.image_identity))
        return error.Word16RootIdentityMismatch;
    if (span.first_epoch != 1 or span.end_epoch_exclusive != span.cpu_count + 1 or
        span.first_step != 0 or span.steps != expected.total_steps or
        span.steps > expected.max_total_steps or
        span.first_pc != expected.admission.initial_pc or
        span.final_pc != expected.final_pc or
        !std.mem.eql(u64, &span.first_registers, &expected.admission.initial_registers) or
        !std.mem.eql(u64, &span.final_registers, &expected.final_registers))
        return error.Word16RootIncompleteExecution;
    if (truths.len != encoded.len or truths.len > 65535) return error.Word16RootTruthRosterMismatch;
    var kio = span.keccak_io;
    var wire = span.secp_wire;
    for (truths, encoded) |truth, item| for (item.claims) |claim| {
        if (truth.family() == .keccak) {
            kio = kio.add(claim);
        } else {
            wire = wire.add(claim);
        }
    };
    if (!span.ram.isZero()) return error.Word16RootUnclosedRam;
    if (!kio.isZero()) return error.Word16RootUnclosedKeccakIo;
    if (!wire.isZero()) return error.Word16RootUnclosedSecpWire;
    return .{ .span = span, .truth_proofs = @intCast(truths.len) };
}

/// Reference implementation of the future complete *native* public root.
/// The complete native receiver must accept every CPU and service STARK, its
/// fixed/MAIN roots, inventory and all typed LogUp relations before folding
/// any authenticated public statements. A SHA-256 digest or this structure
/// cannot replace that physical verification, and a true recursive root must
/// reimplement the fold checks in its own proof-system arithmetic.
pub fn verifyNativeAndFold(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, bundle: *const E.Bundle) !NativeRoot {
    try E.verify(a, setups, truths, expected, bundle);
    if (setups.len == 0 or setups.len != bundle.cpus.len) return error.Word16RootCpuRosterMismatch;
    var first: u64 = 0;
    var root: ?FoldedSpan = null;
    for (bundle.cpus, 0..) |cpu, ordinal| {
        const next = try fromPublicCpu(expected, cpu, ordinal, first);
        first = std.math.add(u64, first, next.steps) catch return error.Word16SpanOverflow;
        root = if (root) |previous| try fold(previous, next) else next;
    }
    return closePublic(expected, root.?, truths, bundle.truths);
}
