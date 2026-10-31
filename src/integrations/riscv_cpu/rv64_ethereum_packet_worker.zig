//! Root-chain control worker: physical proof generation is independent of proof
//! arrival order. A later job's initial boundary remains an OPEN obligation;
//! only the final fresh chain receiver establishes genesis/adjacency/terminal.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const Expected = @import("rv64_ethereum_worker_expected.zig");
const Packet = @import("rv64_prepared_work_packet.zig");
const Batch = @import("rv64_ethereum_prove_batch.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
pub const Result = struct {
    index: u32,
    physical_fragment_verified: bool = true,
    global_chain_accepted: bool = false,
    packet_sha256: [64]u8,
    metrics: Batch.Metrics,
    authority_ns: u64,
    packet_read_ns: u64,
    prove_worker_ns: u64,
    /// Whole invocation through physical proof/publication, before encoding and
    /// publishing the completion record. Includes lock/admission overhead too.
    total_before_completion_ns: u64,
};
pub fn run(a: std.mem.Allocator, config: Request.Config, index: u32) !Result {
    var total = try std.time.Timer.start();
    try Request.validateBudget(config);
    var directory = try std.fs.cwd().openDir(config.output_directory, .{});
    defer directory.close();
    // The inode remains stable: unlinking a lock file permits two concurrent
    // owners of different inodes. OS close releases the lock after crashes.
    const lock_name = try std.fmt.allocPrint(a, "job-{d:0>6}.lock", .{index});
    defer a.free(lock_name);
    var lock = try directory.createFile(lock_name, .{ .read = true, .truncate = false });
    defer lock.close();
    if (!try lock.tryLock(.exclusive)) return error.EthereumWorkerAlreadyRunning;
    defer lock.unlock();
    for ([_][]const u8{ "proof", "json", "stages.json" }) |extension| {
        const name = try std.fmt.allocPrint(a, "batch-{d:0>6}.{s}", .{ index, extension });
        defer a.free(name);
        directory.access(name, .{}) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        return error.EthereumWorkerArtifactsAlreadyExist;
    }
    // init destroys its temporary image and Cache before returning. Only
    // independently derived immutable authority/policy/genesis remain here.
    var phase = try std.time.Timer.start();
    var expected = try Expected.Owner.init(a, config);
    const authority_ns = phase.lap();
    defer expected.deinit();
    const identity = try Packet.identityFor(config, &expected.authority, &expected.policy);
    const name = try std.fmt.allocPrint(a, "jobs/job-{d:0>6}.work", .{index});
    defer a.free(name);
    var file = try directory.openFile(name, .{});
    defer file.close();
    phase.reset();
    var packet = try Packet.read(a, file, .{ .identity = identity, .authority = &expected.authority, .policy = &expected.policy, .state_policy = config.state_policy }, .{ .steps = config.batch_steps });
    const packet_read_ns = phase.lap();
    defer packet.deinit();
    if (packet.metadata.index != index) return error.InvalidEthereumWorkerIndex;
    const public = packet.finished.public;
    const ids = [_]u64{ public.first_call_id, public.secp.add.first_id, public.secp.double.first_id };
    for (ids) |id| if (id == 0) return error.InvalidEthereumServiceCoverage;
    var cursor = Chain.Cursor{
        .root = packet.metadata.before,
        .pc = public.statement.initial_pc,
        .registers = public.statement.initial_registers,
        .steps = packet.metadata.first_step,
        .batches = index,
        .calls = .{ ids[0] - 1, ids[1] - 1, ids[2] - 1 },
        .expected_state_policy = config.state_policy,
    };
    if (index == 0 and (cursor.steps != 0 or !std.mem.eql(u32, &cursor.root, &expected.initial_root) or cursor.pc != expected.initial_pc or !std.mem.eql(u64, &cursor.registers, &expected.initial_registers) or !std.mem.eql(u64, &cursor.calls, &.{ 0, 0, 0 }))) return error.InvalidEthereumWorkerGenesis;
    // For index>0 this is intentionally a conditional fragment. No accepted
    // prefix or execution authority is inferred from packet boundaries.
    phase.reset();
    const metrics = try Batch.provePrepared(a, .{ .authority = &expected.authority, .policy = &expected.policy, .frontier = .{ .detached = .{ .before = packet.metadata.before, .graph = if (packet.native) |*value| value else null } } }, config, &packet.tape, &packet.finished, &cursor, directory, .{});
    const prove_worker_ns = phase.lap();
    const result = Result{ .index = index, .packet_sha256 = std.fmt.bytesToHex(packet.content_digest, .lower), .metrics = metrics, .authority_ns = authority_ns, .packet_read_ns = packet_read_ns, .prove_worker_ns = prove_worker_ns, .total_before_completion_ns = total.read() };
    const json = try std.json.Stringify.valueAlloc(a, result, .{ .whitespace = .indent_2 });
    defer a.free(json);
    const completed = try std.fmt.allocPrint(a, "job-{d:0>6}.completed.json", .{index});
    defer a.free(completed);
    try Receipt.writeExclusive(directory, completed, json);
    try std.posix.fsync(directory.fd);
    // Never write summary.json/checkpoint/verified_batches in this worker.
    return result;
}
