//! Read-only transport/admission diagnostic. Decodes only bounded narrow owners;
//! never constructs a wide trace or proves/accepts an execution fragment.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const Expected = @import("rv64_ethereum_worker_expected.zig");
const Packet = @import("rv64_prepared_work_packet.zig");
const Digest = @import("rv64_authenticated_execution.zig").R.values.Digest;
pub const Result = struct {
    index: u32,
    file_bytes: u64,
    tape_retained_bytes: usize,
    frontier_owned_bytes: usize,
    cells: usize,
    steps: u32,
    division_requests: u32,
    multiplication_requests: u32,
    calls: [3]u32,
    before: Digest,
    after: Digest,
    physical_proof_verified: bool = false,
    global_chain_accepted: bool = false,
};
pub fn run(a: std.mem.Allocator, config: Request.Config, index: u32) !Result {
    try Request.validateBudget(config);
    var expected = try Expected.Owner.init(a, config);
    defer expected.deinit();
    const name = try std.fmt.allocPrint(a, "{s}/jobs/job-{d:0>6}.work", .{ config.output_directory, index });
    defer a.free(name);
    var file = try std.fs.cwd().openFile(name, .{});
    defer file.close();
    var packet = try Packet.read(a, file, .{ .identity = try Packet.identityFor(config, &expected.authority, &expected.policy), .authority = &expected.authority, .policy = &expected.policy, .state_policy = config.state_policy }, .{ .steps = config.batch_steps });
    defer packet.deinit();
    if (packet.metadata.index != index) return error.InvalidEthereumWorkerIndex;
    const public = packet.finished.public;
    return .{ .index = index, .file_bytes = try file.getEndPos(), .tape_retained_bytes = packet.tape.retainedBytes(), .frontier_owned_bytes = if (packet.native) |*value| value.ownedBytes() else 0, .cells = packet.finished.cells.len, .steps = public.statement.steps, .division_requests = public.division_requests, .multiplication_requests = public.multiplication_requests, .calls = .{ public.keccak_calls, public.secp.add.calls, public.secp.double.calls }, .before = packet.metadata.before, .after = packet.metadata.after };
}
