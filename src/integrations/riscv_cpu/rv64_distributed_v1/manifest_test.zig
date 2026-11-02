const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = @import("manifest.zig");
const T = M.T;
const W = @import("wire.zig");
const RW = @import("receipt_wire.zig");
const a = std.testing.allocator;
const Felt = core.fields.m31.M31;
const logs = [_]u32{5} ** 14;
pub fn context() T.Context {
    return .{ .request_id = (1 << 60) + 17, .request_digest = @splat(1), .instance = @splat(2), .program_key = @splat(3), .input = @splat(4), .policy = @splat(5), .terminal = @splat(6), .opcode_map = T.opcodeMapIdentity(), .relation_epoch = (1 << 53) + 7 };
}
fn fixedRoot(allocator: std.mem.Allocator, values: []Felt) !T.CommitmentRoot {
    var scheme = try T.Scheme.init(allocator, T.P.config());
    defer scheme.deinit(allocator);
    var channel = T.P.Channel{};
    try scheme.commitBorrowedStreaming(allocator, &.{.{ .log_size = 5, .values = values }}, 8, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    return .{ .value = roots.items[0] };
}
const Stage = struct {
    allocator: std.mem.Allocator,
    scheme: T.Scheme,
    channel: T.P.Channel,
    spec: T.Spec,
    receipt: T.Receipt,
    fn init(allocator: std.mem.Allocator, ordinal: u32, role: T.Role) !Stage {
        var fixed: [32]Felt = undefined;
        for (&fixed, 0..) |*value, i| value.* = Felt.fromCanonical(@intCast(i));
        const spec = T.Spec{ .ordinal = ordinal, .role = role, .schema = @splat(@intCast(ordinal + 1)), .job_witness = @splat(11), .public_statement = @splat(12), .instance_epoch = (@as(u64, 1) << 40) + ordinal, .first_request = (1 << 53) + 19, .request_count = 9999, .expected_fixed = try fixedRoot(allocator, &fixed), .column_logs = &logs };
        var scheme = try T.Scheme.init(allocator, T.P.config());
        errdefer scheme.deinit(allocator);
        var channel = T.P.Channel{};
        try M.beginStage1(context(), spec, &channel);
        try scheme.commitBorrowedStreaming(allocator, &.{.{ .log_size = 5, .values = &fixed }}, 8, &channel);
        var values: [14 * 32]Felt = undefined;
        var columns: [14]engine.pcs.ColumnEvaluation = undefined;
        for (&columns, 0..) |*column, i| {
            const row = values[i * 32 ..][0..32];
            for (row, 0..) |*value, j| value.* = Felt.fromCanonical(@intCast(100 * ordinal + i + j));
            column.* = .{ .log_size = 5, .values = row };
        }
        try scheme.commitBorrowedStreaming(allocator, &columns, 8, &channel);
        const receipt = try T.fromCommitted(allocator, &scheme, spec);
        return .{ .allocator = allocator, .scheme = scheme, .channel = channel, .spec = spec, .receipt = receipt };
    }
    fn deinit(self: *Stage) void {
        self.scheme.deinit(self.allocator);
    }
};
pub const Fixture = struct {
    cpu: Stage,
    binary: Stage,
    specs: [2]T.Spec,
    receipts: [2]T.Receipt,
    pub fn init() !Fixture {
        var cpu = try Stage.init(a, 0, .cpu);
        errdefer cpu.deinit();
        var binary = try Stage.init(a, 1, .binary);
        errdefer binary.deinit();
        return .{ .cpu = cpu, .binary = binary, .specs = .{ cpu.spec, binary.spec }, .receipts = .{ cpu.receipt, binary.receipt } };
    }
    pub fn expected(self: *const Fixture) M.Expected {
        return .{ .context = context(), .specs = &self.specs };
    }
    pub fn deinit(self: *Fixture) void {
        self.cpu.deinit();
        self.binary.deinit();
    }
};
test "distributed stage1 exports actual PCS roots, complete manifest resumes same locally committed worker" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    try std.testing.expectEqual(@as(u64, 32), manifest.positive_capacity);
    const challenge = try manifest.derive();
    try std.testing.expect(!std.meta.eql(challenge.alu, challenge.binary));
    try std.testing.expect(!std.meta.eql(challenge.binary, challenge.shift));
    const actual = try manifest.resumeWorker(a, 0, &fixture.cpu.scheme, &fixture.cpu.channel);
    try std.testing.expectEqualDeep(challenge, actual);
    try std.testing.expectError(error.Stage1TranscriptMismatch, manifest.resumeWorker(a, 0, &fixture.cpu.scheme, &fixture.cpu.channel));
    var other = fixture.cpu.spec;
    var wrong_logs = logs;
    wrong_logs[0] = 6;
    other.column_logs = &wrong_logs;
    try std.testing.expectError(error.Stage1GeometryMismatch, T.fromCommitted(a, &fixture.cpu.scheme, other));
    other = fixture.cpu.spec;
    other.expected_fixed.value[0] ^= 1;
    try std.testing.expectError(error.Stage1FixedRootMismatch, T.fromCommitted(a, &fixture.cpu.scheme, other));
}
test "distributed barrier rejects omission reorder duplicated role and stale fixed roots before allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.IncompleteDistributedManifest, M.Manifest.init(fail.allocator(), fixture.expected(), fixture.receipts[0..1]));
    var bad = fixture.receipts;
    std.mem.swap(T.Receipt, &bad[0], &bad[1]);
    try std.testing.expectError(error.DistributedInventoryMismatch, M.Manifest.init(fail.allocator(), fixture.expected(), &bad));
    bad = fixture.receipts;
    bad[1] = bad[0];
    try std.testing.expectError(error.DistributedInventoryMismatch, M.Manifest.init(fail.allocator(), fixture.expected(), &bad));
    bad = fixture.receipts;
    bad[0].fixed.value[0] ^= 1;
    try std.testing.expectError(error.DistributedInventoryMismatch, M.Manifest.init(fail.allocator(), fixture.expected(), &bad));
    try std.testing.expect(!fail.has_induced_failure);
}
test "distributed challenge binds peer roots and full64 IDs; RAM and widened register clock remain unsupported" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var original = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer original.deinit();
    var receipts = fixture.receipts;
    receipts[1].shared.value[0] ^= 1;
    var changed = try M.Manifest.init(a, fixture.expected(), &receipts);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(try original.derive(), try changed.derive()));
    var expected = fixture.expected();
    expected.context.request_id += 0x7fff_ffff;
    var full_id = try M.Manifest.init(a, expected, &fixture.receipts);
    defer full_id.deinit();
    try std.testing.expect(!std.meta.eql(try original.derive(), try full_id.derive()));
    expected = fixture.expected();
    expected.context.protocol = .ram64_v2;
    try std.testing.expectError(error.UnsupportedDistributedRamProfile, M.Manifest.init(a, expected, &fixture.receipts));
    expected = fixture.expected();
    expected.context.local_register_clock_bits = 32;
    try std.testing.expectError(error.InvalidDistributedContext, M.Manifest.init(a, expected, &fixture.receipts));
    original.receipts[0].shared.value[0] ^= 1;
    try std.testing.expectError(error.DistributedManifestChanged, original.derive());
}
test "distributed global positive capacity includes padding and rejects characteristic-many CPU requests" {
    var specs: [512]T.Spec = undefined;
    for (&specs, 0..) |*spec, i| spec.* = .{ .ordinal = @intCast(i), .role = .cpu, .schema = @splat(1), .job_witness = @splat(2), .public_statement = @splat(3), .instance_epoch = i, .first_request = i, .request_count = 0, .expected_fixed = .{ .value = @splat(4) }, .column_logs = &.{22} };
    try std.testing.expectError(error.DistributedMassOverflow, M.validateInventory(.{ .context = context(), .specs = &specs }));
}
fn allocated(allocator: std.mem.Allocator, expected: M.Expected, receipts: []const T.Receipt) !void {
    var manifest = try M.Manifest.init(allocator, expected, receipts);
    defer manifest.deinit();
    _ = try manifest.derive();
}
test "distributed manifest owns copied metadata and every allocation failure balances" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(a, allocated, .{ fixture.expected(), &fixture.receipts });
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    fixture.receipts[0].shared.value[0] ^= 1;
    try manifest.validateUnchanged();
}
test "distributed canonical root-only and complete-manifest frames roundtrip without trace values" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const receipt_file = try temp.dir.createFile("root", .{ .read = true });
    defer receipt_file.close();
    try RW.write(receipt_file, context(), fixture.specs[0], fixture.receipts[0]);
    try std.testing.expectEqual(@as(u64, 548 + 14 * 4), try receipt_file.getEndPos());
    try receipt_file.seekTo(0);
    try std.testing.expectEqualDeep(fixture.receipts[0], try RW.read(receipt_file, context(), fixture.specs[0]));
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    const file = try temp.dir.createFile("manifest", .{ .read = true });
    defer file.close();
    try W.write(file, &manifest);
    try file.seekTo(0);
    var loaded = try W.read(a, file, fixture.expected());
    defer loaded.deinit();
    try std.testing.expectEqualDeep(manifest.digest, loaded.digest);
    try std.testing.expectEqualDeep(try manifest.derive(), try loaded.derive());
    try std.testing.expectEqual(context().request_id, loaded.context.request_id);
    try std.testing.expectEqual(fixture.specs[0].first_request, loaded.specs[0].first_request);
}
