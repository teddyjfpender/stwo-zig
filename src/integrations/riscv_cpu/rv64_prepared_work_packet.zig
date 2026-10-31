//! Portable native witness job, not proof or receiver authority. The collector
//! streams borrowed narrow owners into a durable file before advancing Cache;
//! the fresh worker owns decoded values and derives ROM/policy independently.
const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const R = frontend.rv64_air.memory;
const Native = @import("rv64_ethereum_batch.zig");
const H = @import("rv64_work_packet_header.zig");
const IO = @import("rv64_work_packet_io.zig");
const Body = @import("rv64_work_packet_body.zig");
const Public = @import("rv64_work_packet_public.zig");
const Budget = @import("rv64_work_packet_budget.zig");
const Admission = @import("rv64_work_packet_admission.zig");
pub const Identity = H.Identity;
pub const Metadata = H.Metadata;
pub const Expected = H.Expected;
pub const Limits = H.Limits;
pub const Digest = H.Digest;
pub const HEADER_BYTES = H.BYTES;
pub const identityFor = H.identityFor;
pub const programKey = H.programKey;
pub const View = struct { metadata: Metadata, finished: *const Native.Finished, native: ?*const R.native_frontier.Prepared, tape: *const rv.compact_tape.Tape };
pub const Packet = struct {
    allocator: std.mem.Allocator,
    metadata: Metadata,
    finished: Native.Finished,
    native: ?R.native_frontier.Prepared,
    tape: rv.compact_tape.Tape,
    content_digest: Digest,
    pub fn view(self: *const Packet) View {
        return .{ .metadata = self.metadata, .finished = &self.finished, .native = if (self.native) |*value| value else null, .tape = &self.tape };
    }
    pub fn deinit(self: *Packet) void {
        self.tape.deinit();
        if (self.native) |*value| value.deinit();
        self.finished.deinit();
        self.* = undefined;
    }
};
fn header(view: View) !H.Header {
    const finished = view.finished;
    if (finished.cells.len > std.math.maxInt(u32)) return error.WorkPacketResourceLimit;
    const chunks = if (finished.openings) |*value| value.chunks.len else 0;
    if (chunks > std.math.maxInt(u32)) return error.WorkPacketResourceLimit;
    const h = H.Header{ .metadata = view.metadata, .cells = @intCast(finished.cells.len), .chunks = @intCast(chunks), .graph_bytes = if (view.native) |value| try R.native_frontier_wire.encodedBytes(value) else 0, .tape_bytes = try rv.compact_tape_wire.encodedBytes(view.tape) };
    try h.validate(.{});
    return h;
}
pub fn encodedBytes(view: View) !usize {
    return (try header(view)).totalBytes();
}
pub fn validate(view: View) !void {
    _ = try header(view);
    const public = view.finished.public;
    const tape = view.tape;
    if ((public.execution_profile != .ethereum_services_v1 and public.execution_profile != .ethereum_services_v2) or public.arithmetic_policy != .division_multiplication_services_v3 or tape.execution_profile != public.execution_profile or tape.len == 0 or tape.len > tape.storage.len or tape.len != public.statement.steps or tape.initial_clock != view.metadata.first_step or tape.initial_pc != public.statement.initial_pc or tape.storage[tape.len - 1].next_pc != public.statement.final_pc or tape.service_calls.items.len != public.keccak_calls or tape.secp_calls.items.len != @as(u64, public.secp.add.calls) + public.secp.double.calls) return error.InvalidWorkPacketBoundary;
    try Body.validate(view.finished);
    if ((view.native != null) != (view.finished.openings != null)) return error.InvalidWorkPacketGraph;
    if (view.native) |graph| {
        if (graph.witness.geometry != .chunk512 or !std.mem.eql(u32, &graph.witness.before, &view.metadata.before) or !std.mem.eql(u32, &graph.witness.after, &view.metadata.after)) return error.InvalidWorkPacketRoot;
        try graph.validateOpenings(view.finished.openings.?.chunks);
    }
    for (tape.service_calls.items, 0..) |call, i| if (call.call_id != @as(u64, public.first_call_id) + i) return error.InvalidWorkPacketService;
    var counts: [2]u32 = @splat(0);
    for (tape.secp_calls.items) |call| {
        const k: usize = if (call.kind == .add) 0 else 1;
        if (call.call_id != @as(u64, public.secp.firstIds()[k]) + counts[k]) return error.InvalidWorkPacketService;
        counts[k] += 1;
    }
    if (!std.mem.eql(u32, &counts, &public.secp.counts())) return error.InvalidWorkPacketService;
}
/// File must be empty, readable+writable and exclusively owned. Streams fixed
/// bounded buffers; no encoded Tape copy is allocated. Caller owns publication.
pub fn write(file: std.fs.File, view: View) !Digest {
    if (try file.getPos() != 0 or try file.getEndPos() != 0) return error.InvalidWorkPacketFile;
    const h = try header(view);
    try validate(view);
    try file.writeAll(&(try H.encode(h)));
    var writer = IO.Writer{ .file = file };
    try Body.write(&writer, view.finished);
    try writer.flush();
    if (view.native) |graph| try R.native_frontier_wire.write(file, graph);
    try rv.compact_tape_wire.write(file, view.tape);
    if (try file.getEndPos() != try h.totalBytes()) return error.InvalidWorkPacketSection;
    const digest = try IO.digest(file, try h.totalBytes());
    try file.seekTo(IO.DIGEST_OFFSET);
    try file.writeAll(&digest);
    try file.seekTo(try h.totalBytes());
    return digest;
}
/// Validates outer identity/digest/section and decoded allocation budgets before
/// any witness allocation. Input file must remain immutable for this call.
pub fn read(a: std.mem.Allocator, file: std.fs.File, expected: Expected, limits: Limits) !Packet {
    try expected.policy.validateImmutableExecution();
    try file.seekTo(0);
    var raw: [H.BYTES]u8 = undefined;
    try IO.exact(file, &raw);
    const h = try H.decode(&raw, try file.getEndPos(), expected, limits);
    if (!std.mem.eql(u8, &h.content_digest, &(try IO.digest(file, try h.totalBytes())))) return error.WorkPacketContentMismatch;
    try file.seekTo(H.BYTES);
    var public_raw: [Public.BYTES]u8 = undefined;
    try IO.exact(file, &public_raw);
    const public = try Public.decode(&public_raw, expected.authority);
    if ((public.execution_profile != .ethereum_services_v1 and public.execution_profile != .ethereum_services_v2) or public.arithmetic_policy != .division_multiplication_services_v3 or public.state_policy != expected.state_policy) return error.WorkPacketAuthorityMismatch;
    try Budget.check(file, h, public.statement.steps, limits);
    try Admission.check(file, h, public, expected.authority);
    try file.seekTo(H.BYTES + Public.BYTES);
    var reader = IO.Reader{ .file = file, .remaining = (try h.bodyBytes()) - Public.BYTES };
    var finished = try Body.read(a, &reader, public, h.cells, h.chunks);
    errdefer finished.deinit();
    try reader.finish();
    const graph_end = try std.math.add(usize, H.BYTES + try h.bodyBytes(), h.graph_bytes);
    var native: ?R.native_frontier.Prepared = if (h.graph_bytes == 0) null else try R.native_frontier_wire.read(a, file, .{ .bytes = h.graph_bytes });
    errdefer if (native) |*value| value.deinit();
    if (try file.getPos() != graph_end) return error.InvalidWorkPacketSection;
    var tape = try rv.compact_tape_wire.readTail(a, file, .{ .bytes = h.tape_bytes, .steps = @min(limits.steps, public.statement.steps) });
    errdefer tape.deinit();
    if (try rv.compact_tape_wire.encodedBytes(&tape) != h.tape_bytes) return error.InvalidWorkPacketSection;
    const result = Packet{ .allocator = a, .metadata = h.metadata, .finished = finished, .native = native, .tape = tape, .content_digest = h.content_digest };
    try validate(result.view());
    return result;
}
/// Atomic exclusive publication. A retry of the exact same job is idempotent;
/// a different job at this name is rejected. File and parent directory sync
/// precede success, so a Native.Handoff callback can safely advance Cache next.
pub fn writeAtomic(a: std.mem.Allocator, directory: std.fs.Dir, name: []const u8, view: View) !Digest {
    if (name.len == 0 or std.mem.indexOfAny(u8, name, "/\\\x00") != null or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidWorkPacketName;
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.UnsupportedWorkPacketPublication;
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const pending = try std.fmt.allocPrint(a, ".{s}.{s}.pending", .{ name, std.fmt.bytesToHex(nonce, .lower) });
    defer a.free(pending);
    const file = try directory.createFile(pending, .{ .read = true, .exclusive = true, .mode = 0o600 });
    defer file.close();
    defer directory.deleteFile(pending) catch {};
    const digest = try write(file, view);
    try file.sync();
    std.posix.linkat(directory.fd, pending, directory.fd, name, 0) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try directory.openFile(name, .{});
            defer existing.close();
            const bytes = try encodedBytes(view);
            if (try existing.getEndPos() != bytes) return error.WorkPacketPublicationConflict;
            var recorded: Digest = undefined;
            try existing.seekTo(IO.DIGEST_OFFSET);
            try IO.exact(existing, &recorded);
            if (!std.mem.eql(u8, &digest, &recorded) or !std.mem.eql(u8, &digest, &(try IO.digest(existing, bytes)))) return error.WorkPacketPublicationConflict;
            try existing.sync();
        },
        else => return err,
    };
    var parent = try directory.openDir(".", .{});
    defer parent.close();
    try std.posix.fsync(parent.fd);
    return digest;
}
