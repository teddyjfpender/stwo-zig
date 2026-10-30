//! Exact original-proof parity for durable compact PCS handoff, plus framing,
//! budget and noncanonical-payload rejection. Raw-cell restoration is exercised
//! separately by the whole streaming execution test.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Caller = @import("../block_v7_caller_active_proof_v1.zig");
const Raw = @import("../block_v5_caller_columns_stage_v1.zig");
const Store = @import("../block_v6_cpu_scheme_store_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
pub const Saved = struct {
    a: std.mem.Allocator,
    dir: std.testing.TmpDir,
    pin: Store.Pin,
    raw: Raw.Pin,
    descriptor: Raw.Descriptor,
    identity: [32]u8,
    roots: [3][32]u8,
    config: core.pcs.PcsConfig,
    logs: [3][]u32,
    pub fn init(a: std.mem.Allocator, stage: *Caller.ForBackend(Cpu).Stage, pin: Caller.Pin) !Saved {
        var dir = std.testing.tmpDir(.{});
        errdefer dir.cleanup();
        const fixed = try a.dupe(u32, stage.schedule.fixed);
        errdefer a.free(fixed);
        const main = try a.dupe(u32, stage.schedule.main);
        errdefer a.free(main);
        const access = try stage.schedule.witnessLogs();
        errdefer a.free(access);
        const descriptor = Raw.Descriptor{ .statement = pin.statement.*, .total_steps = pin.total_steps, .index = pin.index, .frame = pin.frame, .config = pin.config, .roots = pin.roots, .key_id = try @import("../block_v5_precompile_protocol_v1.zig").keyId(pin.statement, pin.total_steps, pin.config, pin.roots[0]) };
        const raw = try Raw.write(a, dir.dir, "caller.raw", stage.witness, &descriptor, .{});
        var self = Saved{ .raw = raw, .descriptor = descriptor, .a = a, .dir = dir, .pin = undefined, .identity = (try pin.entry(a)).identity, .roots = stage.first.roots, .config = pin.config, .logs = .{ fixed, main, access } };
        self.pin = try Store.write(a, dir.dir, "caller.pcs", self.admission(), &stage.first.scheme, .{ .max_columns = 1 << 16 });
        try std.testing.expect(self.pin.coefficient_bytes != 0);
        return self;
    }
    fn admission(self: *const Saved) Store.Admission {
        return .{ .identity = self.identity, .config = self.config, .roots = &self.roots, .logs = &self.logs, .retain_coefficients = true };
    }
    pub fn deinit(self: *Saved) void {
        for (self.logs) |logs| self.a.free(logs);
        self.dir.cleanup();
    }
    pub fn qualify(self: *Saved, pin: Caller.Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry, original: *const Caller.Proof, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
        const a = self.a;
        const limits = Store.Limits{ .max_columns = 1 << 16 };
        var wrong = self.admission();
        wrong.identity[0] ^= 1;
        try std.testing.expectError(error.InvalidProviderCheckpointScope, Store.load(a, self.dir.dir, "caller.pcs", wrong, self.pin, limits));
        var small = limits;
        small.max_loaded_bytes = self.pin.loaded_bytes - 1;
        try std.testing.expectError(error.ProviderCheckpointResourceLimit, Store.load(a, self.dir.dir, "caller.pcs", self.admission(), self.pin, small));
        const file = try self.dir.dir.openFile("caller.pcs", .{ .mode = .read_write });
        defer file.close();
        // Header48 + tree framing8 + first column log4, then first M31.
        var original_cell: [4]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&original_cell, 60));
        try file.pwriteAll(&.{ 255, 255, 255, 255 }, 60);
        try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, Store.load(a, self.dir.dir, "caller.pcs", self.admission(), self.pin, limits));
        try file.pwriteAll(&original_cell, 60);
        const raw = try Raw.reconstruct(a, self.dir.dir, "caller.raw", &self.descriptor, self.raw, .{});
        defer raw.deinit();
        var scheme = try Store.load(a, self.dir.dir, "caller.pcs", self.admission(), self.pin, limits);
        var owns = true;
        defer if (owns) scheme.deinit(a);
        const stage = try Caller.ForBackend(Cpu).Stage.fromRestored(a, &raw.witness, pin.frame, pin.index, self.roots, &scheme);
        owns = false;
        defer stage.deinit();
        var restored = try Caller.ForBackend(Cpu).prove(a, stage, pin, epoch, entries, pool);
        defer restored.deinit(a);
        _ = try Caller.ForBackend(Cpu).verify(a, &restored, pin, epoch, entries);
        var left = std.Io.Writer.Allocating.init(a);
        defer left.deinit();
        var right = std.Io.Writer.Allocating.init(a);
        defer right.deinit();
        const wire = @import("interop_postcard");
        try wire.serializeProof(core.proof_suites.Blake3.Hasher, &left.writer, original.stark);
        try wire.serializeProof(core.proof_suites.Blake3.Hasher, &right.writer, restored.stark);
        try std.testing.expectEqualSlices(u8, left.written(), right.written());
        try std.testing.expectEqualDeep(original.arithmetic, restored.arithmetic);
        try std.testing.expectEqualDeep(original.relations, restored.relations);
        std.debug.print("V7_ACTIVE_CHECKPOINT bytes={d} coefficients={d} byte_identical=true identity_cap_noncanonical_rejected=true fresh_verified=true\n", .{ self.pin.bytes, self.pin.coefficient_bytes });
    }
};
