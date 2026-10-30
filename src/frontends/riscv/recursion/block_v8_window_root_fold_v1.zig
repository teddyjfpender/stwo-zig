//! Bounded, recursively reusable window-root fold. Each child verifies its
//! original typed parent AIR/PCS and exact protocol-specific public supply.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Profile = @import("block_v8_window_root_profile_v1.zig");
const Source = @import("block_v8_window_root_source_v1.zig");
const Roster = @import("block_v8_window_root_roster_v1.zig");
const Protocol = @import("block_v8_window_root_protocol_v1.zig");
const Statements = @import("block_v8_window_root_statement_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const ParentVerified = @import("blake3_native_parent_verifier.zig").Verified;
pub const Stats = struct {
    fixed_compile_ns: u64 = 0,
    fixed_commit_ns: u64 = 0,
    key_admission_ns: u64 = 0,
    witness_ns: u64 = 0,
    plan_ns: u64 = 0,
    proof_ns: u64 = 0,
    encode_ns: u64 = 0,
    whole_ns: u64 = 0,
    retained_rows_bytes: usize = 0,
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    span: Statements.WindowSpan,
    /// Nominated from the actual produced proof; never verifier authority.
    main_root: [32]u8,
    stats: Stats = .{},
    pub fn deinit(v: *Artifact) void {
        v.allocator.free(v.bytes);
        v.* = undefined;
    }
};
fn spans(children: []const *const Profile.Owned) !Statements.WindowSpan {
    if (children.len < 2 or children.len > 4) return error.InvalidB8WindowFanIn;
    var list: [4]Statements.WindowSpan = undefined;
    for (children, 0..) |child, i| {
        try child.validate();
        list[i] = child.span;
    }
    return Statements.merge(list[0..children.len]);
}
fn sources(a: std.mem.Allocator, children: []const *const Profile.Owned) ![]Source.Source {
    const out = try a.alloc(Source.Source, children.len);
    for (out, children) |*v, p| v.* = .{ .root = p };
    return out;
}
pub fn produce(a: std.mem.Allocator, children: []const *const Profile.Owned, captures: []const Source.Capture) !Artifact {
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{};
    const span = try spans(children);
    const src = try sources(a, children);
    defer a.free(src);
    const extra = try @import("air/block_v8_window_root_composition_v1.zig").spanValues(a, span);
    defer a.free(extra);
    var setup = try Roster.Owned.deriveWithOptions(a, src, extra, .{ .global_g_repartition = true });
    defer setup.deinit();
    stats.fixed_compile_ns = phase.lap();
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed = try Fixed.deriveCommitted(a, setup.fixed, setup.context, .csp_q70_pow26);
    defer committed.deinit();
    stats.fixed_commit_ns = phase.lap();
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(committed.key, setup.wires, &expected);
    const admitted = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    stats.key_admission_ns = phase.lap();
    var rows = try setup.liveWithWorkers(a, src, captures, 1);
    defer rows.deinit();
    stats.witness_ns = phase.lap();
    stats.retained_rows_bytes = try rows.retainedBytes();
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &rows, admitted, &committed);
    defer plan.deinit();
    setup.releaseCompilerState();
    stats.plan_ns = phase.lap();
    var proof = try plan.proveConsuming(a, &rows);
    defer proof.deinit();
    stats.proof_ns = phase.lap();
    const bytes = try Parent.codec.encode(a, &proof, &admitted);
    stats.encode_ns = phase.lap();
    stats.whole_ns = whole.read();
    return .{ .allocator = a, .bytes = bytes, .span = span, .main_root = proof.proof.?.commitment_scheme_proof.commitments.items[1], .stats = stats };
}
/// No child successful receipt or capture is required at receiving. Only each
/// independently reconstructed child profile and the externally expected span.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, children: []const *const Profile.Owned, expected_span: Statements.WindowSpan) !ParentVerified {
    const span = try spans(children);
    if (!std.meta.eql(span, expected_span)) return error.UntrustedB8FoldCoverage;
    const src = try sources(a, children);
    defer a.free(src);
    const extra = try @import("air/block_v8_window_root_composition_v1.zig").spanValues(a, span);
    defer a.free(extra);
    var setup = try Roster.Owned.deriveWithOptions(a, src, extra, .{ .global_g_repartition = true });
    defer setup.deinit();
    const geometry = try @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, setup.fixed, setup.context, .csp_q70_pow26);
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(geometry, setup.wires, &expected);
    const admitted = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    var decoded = try Parent.codec.decode(a, bytes, &admitted);
    return Parent.verify(&decoded, &admitted);
}
pub fn deriveProfile(a: std.mem.Allocator, children: []const *const Profile.Owned, main_root: [32]u8) !*Profile.Owned {
    const span = try spans(children);
    const src = try sources(a, children);
    defer a.free(src);
    const extra = try @import("air/block_v8_window_root_composition_v1.zig").spanValues(a, span);
    defer a.free(extra);
    var setup = try Roster.Owned.deriveWithOptions(a, src, extra, .{ .global_g_repartition = true });
    defer setup.deinit();
    const geometry = try @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, setup.fixed, setup.context, .csp_q70_pow26);
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(geometry, setup.wires, &expected);
    const admitted = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    return Profile.Owned.fromCompiled(a, &admitted, setup.values, Protocol.CLAIM_TAG, span, main_root);
}
