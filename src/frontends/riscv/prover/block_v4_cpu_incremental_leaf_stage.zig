//! Private, provisional recursive-leaf staging during incremental core
//! verification. Files acquire no block authority until the core and exact
//! forest have both freshly verified; callers publish a complete manifest only
//! after those gates succeed.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const opcode = @import("block_execution_sidecar_batch_v2.zig");
const seal = @import("block_memory_source_seal_v2.zig").SourceSeal;
const span = @import("../recursion/span_statement_blake3.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const staged_leaf = @import("block_v4_cpu_staged_recursive_leaf_v3.zig");
const incremental = @import("block_v4_cpu_incremental_core_receiver.zig");
const execution = @import("block_v4_cpu_incremental_execution_receiver.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const MAX_LEAF_BYTES: usize = 256 * 1024 * 1024;

pub const Entry = struct {
    byte_len: usize,
    sha256: [32]u8,
    admission: parent.protocol.Admission,
    descriptor: linked.Descriptor,
};

pub const Capture = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    profile: parent.protocol.Profile,
    entries: []Entry,
    next: usize = 0,

    pub fn deinit(self: *Capture) void {
        self.a.free(self.entries);
        self.* = undefined;
    }

    pub fn path(index: usize, buffer: *[64]u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "block-v4-leaf-{d}.proof", .{index});
    }

    pub fn load(self: *const Capture, index: usize) ![]u8 {
        if (index >= self.next) return error.MissingStagedRecursiveLeaf;
        if (self.entries[index].byte_len > MAX_LEAF_BYTES) return error.StagedRecursiveLeafTooLarge;
        var buffer: [64]u8 = undefined;
        const name = try path(index, &buffer);
        var file = try self.dir.openFile(name, .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(self.a, self.entries[index].byte_len);
        errdefer self.a.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (bytes.len != self.entries[index].byte_len or
            !std.meta.eql(digest, self.entries[index].sha256))
            return error.TamperedStagedRecursiveLeaf;
        return bytes;
    }

    fn observer(self: *Capture) execution.FreshLeafObserver {
        return .{ .context = self, .on_fresh_leaf = onFreshLeaf };
    }

    fn onFreshLeaf(context: *anyopaque, index: u32, native_bytes: []const u8, prepared: *const Native.PreparedVerifier, native_key_id: [32]u8, statement: span.SpanStatement, bound: seal, receipt: *const opcode.VerifiedExecutionReceipt) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (index != self.next or index >= self.entries.len)
            return error.InvalidStagedRecursiveLeafOrder;
        // The current recursive proof API takes a mutable verifier pointer;
        // incremental admission revalidates its public shape after this hook.
        var produced = try staged_leaf.prove(self.a, native_bytes, @constCast(prepared), native_key_id, statement, bound, receipt, self.profile);
        defer produced.deinit(self.a);
        if (produced.bytes.len > MAX_LEAF_BYTES) return error.StagedRecursiveLeafTooLarge;
        var name_buffer: [64]u8 = undefined;
        const name = try path(index, &name_buffer);
        var file = try self.dir.createFile(name, .{ .exclusive = true });
        errdefer self.dir.deleteFile(name) catch {};
        defer file.close();
        try file.writeAll(produced.bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(produced.bytes, &digest, .{});
        self.entries[index] = .{
            .byte_len = produced.bytes.len,
            .sha256 = digest,
            .admission = produced.admission,
            .descriptor = produced.descriptor,
        };
        self.next += 1;
    }
};

pub const Result = struct {
    verified_core: incremental.Verified,
    staged: Capture,

    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        self.verified_core.deinit(a);
        self.staged.deinit();
        self.* = undefined;
    }
};

/// Reuses one live prepared verifier per leaf. The observer only writes
/// provisional bytes and cannot change a proof claim or bypass core closure.
pub fn verifyAndStage(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, dir: std.fs.Dir, profile: parent.protocol.Profile) !Result {
    if (!std.meta.eql(profile.config(), config)) return error.UnexpectedStagedRecursiveSecurity;
    if (trusted.native_key_ids.len == 0 or trusted.native_key_ids.len > 1024)
        return error.InvalidStagedRecursiveLeafCount;
    const entries = try a.alloc(Entry, trusted.native_key_ids.len);
    var capture = Capture{ .a = a, .dir = dir, .profile = profile, .entries = entries };
    errdefer {
        for (0..capture.next) |index| {
            var buffer: [64]u8 = undefined;
            const name = Capture.path(index, &buffer) catch continue;
            dir.deleteFile(name) catch {};
        }
        capture.deinit();
    }
    const verified = try incremental.verifyWithLeafObserver(a, product, trusted, config, capture.observer());
    if (capture.next != entries.len) {
        var owned = verified;
        owned.deinit(a);
        return error.IncompleteStagedRecursiveLeaves;
    }
    return .{ .verified_core = verified, .staged = capture };
}

test "staged recursive leaf bytes are hash checked on bounded reload" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const entries = try a.alloc(Entry, 1);
    var capture = Capture{ .a = a, .dir = tmp.dir, .profile = .csp_q70_pow26, .entries = entries, .next = 1 };
    defer capture.deinit();
    const bytes = [_]u8{ 1, 2, 3 };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &digest, .{});
    entries[0] = .{ .byte_len = bytes.len, .sha256 = digest, .admission = undefined, .descriptor = undefined };
    var file = try tmp.dir.createFile("block-v4-leaf-0.proof", .{});
    try file.writeAll(&bytes);
    file.close();
    const loaded = try capture.load(0);
    defer a.free(loaded);
    try std.testing.expectEqualSlices(u8, &bytes, loaded);
    file = try tmp.dir.createFile("block-v4-leaf-0.proof", .{ .truncate = true });
    try file.writeAll(&.{ 1, 9, 3 });
    file.close();
    try std.testing.expectError(error.TamperedStagedRecursiveLeaf, capture.load(0));
}

test "recursive staging rejects a mismatched security profile before proofs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.UnexpectedStagedRecursiveSecurity, verifyAndStage(std.testing.allocator, undefined, undefined, parent.protocol.PCS_CONFIG, tmp.dir, .csp_q70_pow26));
}
