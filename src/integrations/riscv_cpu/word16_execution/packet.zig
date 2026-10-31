//! Transport/advice reader for the new execution protocol. Legacy Poseidon
//! graph/roots are skipped after bounded SHA/admission checks; they establish
//! no INIT, terminal or global-memory authority in this protocol.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const CPU = @import("../rv64_keccak_cpu.zig");
const H = @import("../rv64_work_packet_header.zig");
const IO = @import("../rv64_work_packet_io.zig");
const Public = @import("../rv64_work_packet_public.zig");
const Budget = @import("../rv64_work_packet_budget.zig");
const Admission = @import("../rv64_work_packet_admission.zig");
const Image = @import("expected_image.zig");
const Request = @import("../rv64_ethereum_request.zig");
pub const Packet = struct {
    metadata: H.Metadata,
    public: CPU.Public,
    tape: rv.compact_tape.Tape,
    opcode_counts: Admission.OpcodeCounts,
    content_digest: H.Digest,
    pub fn deinit(self: *Packet) void {
        self.tape.deinit();
        self.* = undefined;
    }
};
/// File must remain immutable. The independently loaded expected image owns
/// the program and policy borrowed by the returned public statement.
pub fn read(a: std.mem.Allocator, file: std.fs.File, image: *const Image.Owner, config: Request.Config) !Packet {
    try Request.validateBudget(config);
    try image.policy.validateImmutableExecution();
    const expected = H.Expected{ .identity = try H.identityFor(config, &image.authority, &image.policy), .authority = &image.authority, .policy = &image.policy, .state_policy = config.state_policy };
    const limits = H.Limits{ .steps = config.batch_steps };
    try file.seekTo(0);
    var raw: [H.BYTES]u8 = undefined;
    try IO.exact(file, &raw);
    const header = try H.decode(&raw, try file.getEndPos(), expected, limits);
    if (!std.mem.eql(u8, &header.content_digest, &(try IO.digest(file, try header.totalBytes())))) return error.WorkPacketContentMismatch;
    try file.seekTo(H.BYTES);
    var public_raw: [Public.BYTES]u8 = undefined;
    try IO.exact(file, &public_raw);
    const public = try Public.decode(&public_raw, &image.authority);
    if (public.execution_profile != .ethereum_services_v2 or public.arithmetic_policy != .division_multiplication_services_v3 or public.state_policy != config.state_policy) return error.WorkPacketAuthorityMismatch;
    try Budget.check(file, header, public.statement.steps, limits);
    const counts = try Admission.check(file, header, public, &image.authority);
    const tape_start = try std.math.add(usize, H.BYTES + try header.bodyBytes(), header.graph_bytes);
    try file.seekTo(tape_start);
    var tape = try rv.compact_tape_wire.readTail(a, file, .{ .bytes = header.tape_bytes, .steps = @min(limits.steps, public.statement.steps) });
    errdefer tape.deinit();
    if (try rv.compact_tape_wire.encodedBytes(&tape) != header.tape_bytes or tape.execution_profile != public.execution_profile or tape.len == 0 or tape.len != public.statement.steps or tape.initial_clock != header.metadata.first_step or tape.initial_pc != public.statement.initial_pc or tape.storage[tape.len - 1].next_pc != public.statement.final_pc or tape.service_calls.items.len != public.keccak_calls or tape.secp_calls.items.len != @as(u64, public.secp.add.calls) + public.secp.double.calls) return error.InvalidWorkPacketBoundary;
    for (tape.service_calls.items, 0..) |call, i| if (call.call_id != @as(u64, public.first_call_id) + i) return error.InvalidWorkPacketService;
    var secp_counts: [2]u32 = @splat(0);
    for (tape.secp_calls.items) |call| {
        const k: usize = if (call.kind == .add) 0 else 1;
        if (call.call_id != @as(u64, public.secp.firstIds()[k]) + secp_counts[k]) return error.InvalidWorkPacketService;
        secp_counts[k] += 1;
    }
    if (!std.mem.eql(u32, &secp_counts, &public.secp.counts())) return error.InvalidWorkPacketService;
    return .{ .metadata = header.metadata, .public = public, .tape = tape, .opcode_counts = counts, .content_digest = header.content_digest };
}
