//! Decode native verified captures into synchronous borrowed source views.
//! These helpers are witness adapters, not execution or topology admission.
//! All source buffers die after visit; consumers must emit/copy before return.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("../full_p2_common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const R = @import("../../word16_global_execution/services/roster.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Request = @import("../../word16_global_execution/services/protocol.zig").Request;
const CPU = @import("worker.zig");
const D = @import("../sponge_local_gkr/worker.zig");
const K = @import("../truth_local_gkr/worker.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Capture = core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H);
pub const View = @import("source_view.zig").View;
pub const Sink = struct {
    context: *anyopaque,
    visit: *const fn (*anyopaque, std.mem.Allocator, View) anyerror!void,
};
pub fn cpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: Request, span: T.OpTowerSpan, first: [T.FAMILIES]u32, ordinal: u32, key: *const @import("key.zig").Key, manifest: [36]u8, main: [36]u8, encoded: *const CPU.Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    var roster = try @import("frame.zig").Roster.init(a, setup, request.sponge.calls, key.frontier_log, request.base.epoch, ordinal);
    defer roster.deinit();
    var local = try @import("native.zig").decode(a, roster.instances, encoded.local);
    defer local.deinit();
    const shape = try @import("capture.zig").geometry(scratch, setup, key);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .cpu = .{ .setup = setup, .request = request, .span = span, .first = first, .key = key, .expected = .{ .ordinal = ordinal, .statement = try key.statement(setup, request, first, span, ordinal) }, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &local.proof, .shape = &shape, .values = &values } });
}
pub fn detached(a: std.mem.Allocator, worker: *const D.Worker, encoded: *const D.Encoded, manifest: [36]u8, main: [36]u8, sink: Sink) !void {
    var capture: Capture = undefined;
    _ = try D.verifyWithCapture(a, worker.geometry, worker.key, worker.expected.ordinal, manifest, main, encoded, &capture);
    defer capture.deinit(a);
    return detachedCaptured(a, worker.key, worker.geometry, worker.expected.ordinal, manifest, main, encoded, &capture, sink);
}
/// Reuse the receiver's existing fresh physical capture; do not verify the
/// native proof a second time while constructing its recursive source view.
pub fn detachedCaptured(a: std.mem.Allocator, key: *const @import("../sponge_local_gkr/key.zig").Key, geometry: @import("../sponge_local_gkr/authority.zig").Geometry, ordinal: u32, manifest: [36]u8, main: [36]u8, encoded: *const D.Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    var local = try @import("../sponge_local_gkr/native.zig").decode(a, geometry, encoded.local);
    defer local.deinit();
    const shape = try @import("../sponge_local_gkr/capture.zig").geometry(scratch, geometry, key);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .detached = .{ .key = key, .geometry = geometry, .ordinal = ordinal, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &local.proof, .shape = &shape, .values = &values } });
}
pub fn truth(a: std.mem.Allocator, key: *const K.Key, declaration: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const K.Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    const shapes = try @import("../truth_local_gkr/authority.zig").shapes(declaration);
    var local = try @import("../truth_local_gkr/native.zig").decode(a, shapes, encoded.local);
    defer local.deinit();
    const shape = try @import("../truth_local_gkr/statement.zig").geometry(scratch, key, declaration);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .truth = .{ .key = key, .truth = declaration, .expected = expected, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } });
}

/// Caller has physically verified encoded under the concrete independently
/// derived source key. Capture/proof/local buffers are borrowed only until visit.
pub fn classicTruth(a: std.mem.Allocator, key: *const @import("../pure_p2_truth_worker.zig").Key, declaration: R.Truth, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const @import("../pure_p2_truth_worker.zig").Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    const shape = try @import("../pure_p2_truth_statement.zig").geometry(scratch, key, declaration);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .classic_truth = .{ .key = key, .truth = declaration, .expected = expected, .manifest = manifest, .main = main, .claims = encoded.claims, .shape = &shape, .values = &values } });
}
pub fn classicMiller(a: std.mem.Allocator, key: *const @import("../pure_p2_tower_worker.zig").Key, span: @import("../pure_p2_tower_worker.zig").Span, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const @import("../pure_p2_tower_worker.zig").Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    const shape = try @import("../pure_p2_tower_statement.zig").geometry(scratch, key);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .classic_miller = .{ .key = key, .span = span, .expected = expected, .manifest = manifest, .main = main, .claims = encoded.claims, .shape = &shape, .values = &values } });
}
pub fn localMiller(a: std.mem.Allocator, key: *const @import("../miller_local_gkr/worker.zig").Key, span: @import("../miller_local_gkr/worker.zig").Span, expected: Manifest.Expected, manifest: [36]u8, main: [36]u8, encoded: *const @import("../miller_local_gkr/worker.zig").Encoded, capture: *const Capture, sink: Sink) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
    defer parsed.deinit(a);
    var local = try @import("../miller_local_gkr/native.zig").decode(a, try key.geometry(span), encoded.local);
    defer local.deinit();
    const shape = try @import("../miller_local_gkr/statement.zig").geometry(scratch, key, span);
    const values = try V.proof.fromNative(scratch, &parsed, capture, &shape);
    try sink.visit(sink.context, a, .{ .local_miller = .{ .key = key, .span = span, .expected = expected, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } });
}
