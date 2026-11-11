//! Verified native captures -> borrowed concrete source views. No callback
//! may retain shape/local-proof pointers or claim execution acceptance.
const std = @import("std");
const Bundle = @import("pure_p2_op_bundle.zig");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const GkrTemplate = @import("pure_p2_gkr_template.zig");
const Views = @import("pure_p2_root_source_view.zig");
fn cpu(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.CpuVerified) !void {
    const sink: *const Views.Sink = @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), v.setup, v.key.profile.config());
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    const local = v.stage_one.local orelse return error.MissingOpRecursiveReceipt;
    const source = Views.View{ .cpu = .{ .op_span = v.span, .setup = v.setup, .request = v.request, .first = v.first_ids, .expected = v.expected, .key = v.key, .manifest = v.manifest.digest, .main = main, .receipt = local.receipt, .claims = v.encoded.claims, .child = local.proof, .shape = &shape, .values = &values } };
    const template = try GkrTemplate.fromProof(a, v.expected.local_instances orelse return error.MissingOpRecursiveReceipt, local.proof);
    var token = Views.Template{ .bytes = template };
    defer token.deinit(a);
    try sink.run(a, .{ .ordinal = v.ordinal, .main = main, .receipt = local.receipt, .claims = v.encoded.claims, .view = source, .kind = "CPU", .template = &token });
}
fn truth(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.TruthVerified) !void {
    const sink: *const Views.Sink = @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("pure_p2_truth_statement.zig").geometry(arena.allocator(), v.key, v.truth);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    const source = Views.View{ .catalog = .{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .claims = v.encoded.claims, .shape = &shape, .values = &values } };
    var token = Views.Template{ .bytes = null };
    try sink.run(a, .{ .ordinal = v.ordinal, .main = main, .receipt = null, .claims = v.encoded.claims, .view = source, .kind = @tagName(v.truth.family()), .template = &token });
}
fn localTruth(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.LocalTruthVerified) !void {
    const sink: *const Views.Sink = @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    const shapes = try @import("truth_local_gkr/authority.zig").shapes(v.truth);
    var local = try @import("truth_local_gkr/native.zig").decode(a, shapes, v.encoded.local);
    defer local.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("truth_local_gkr/statement.zig").geometry(arena.allocator(), v.key, v.truth);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    const source = Views.View{ .local_catalog = .{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .receipt = v.encoded.receipt, .claims = v.encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } };
    const instances = @import("truth_local_gkr/native.zig").instances(shapes);
    const template = try GkrTemplate.Truth.fromProof(a, &instances, &local.proof);
    var token = Views.Template{ .bytes = template };
    defer token.deinit(a);
    try sink.run(a, .{ .ordinal = v.ordinal, .main = main, .receipt = v.encoded.receipt, .claims = &v.encoded.claims, .view = source, .kind = @tagName(v.truth.family()), .template = &token });
}
fn localMiller(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.MillerLocalVerified) !void {
    const sink: *const Views.Sink = @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    const geometry = try v.key.geometry(v.span);
    var local = try @import("miller_local_gkr/native.zig").decode(a, geometry, v.encoded.local);
    defer local.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("miller_local_gkr/statement.zig").geometry(arena.allocator(), v.key, v.span);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    const source = Views.View{ .local_miller = .{ .key = v.key, .span = v.span, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .receipt = v.encoded.receipt, .claims = v.encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } };
    const instances = try geometry.instances();
    const template = try GkrTemplate.fromProofFor(a, &instances, &local.proof);
    var token = Views.Template{ .bytes = template };
    defer token.deinit(a);
    try sink.run(a, .{ .ordinal = v.ordinal, .main = main, .receipt = v.encoded.receipt, .claims = &v.encoded.claims, .view = source, .kind = "Miller-local-GKR", .template = &token });
}
fn miller(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.MillerVerified) !void {
    const sink: *const Views.Sink = @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("pure_p2_tower_statement.zig").geometry(arena.allocator(), v.key);
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const main = native.commitment_scheme_proof.commitments.items[1];
    const source = Views.View{ .miller = .{ .key = v.key, .span = v.span, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .claims = v.encoded.claims, .shape = &shape, .values = &values } };
    var token = Views.Template{ .bytes = null };
    try sink.run(a, .{ .ordinal = v.ordinal, .main = main, .receipt = null, .claims = &v.encoded.claims, .view = source, .kind = "Miller", .template = &token });
}

pub fn hooks(sink: *Views.Sink) Bundle.Hooks {
    return .{ .context = sink, .cpu = cpu, .truth = truth, .truth_local = localTruth, .miller = miller, .miller_local = localMiller };
}

test {
    _ = @import("pure_p2_native_source_hooks_test.zig");
}
