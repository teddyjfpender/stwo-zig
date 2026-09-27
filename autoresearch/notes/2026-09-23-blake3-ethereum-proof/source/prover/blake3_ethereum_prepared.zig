//! Persistent caller-admitted Ethereum statement, fixed root and PCS geometry.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const native_mod = @import("../air/statement.zig");
const extension_mod = @import("blake3_ethereum_statement.zig");
const protocol = @import("blake3_ethereum_protocol.zig");
const base = @import("blake3_execution_protocol.zig");
const plans = @import("blake3_commitment_plan.zig");
const Hashes = @import("blake3_commitment_columns.zig").Owner;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        native: native_mod.Blake3ExecutionStatement,
        extension: extension_mod.Statement,
        config: core.pcs.PcsConfig,
        plan: plans.Plan = undefined,
        plan_id: [32]u8,
        hashes: ?*Hashes = null,
        root: [32]u8 = undefined,
        id: [32]u8 = undefined,
        logs: [3][]u32 = undefined,
        pub fn init(a: std.mem.Allocator, native: *const native_mod.Blake3ExecutionStatement, extension: extension_mod.Statement, pin: plans.Admission, config: core.pcs.PcsConfig) !*Self {
            try native.validateBlake3ExecutionWithExternal(extension.counts.external_retirements);
            try pin.validatePublic(&native.public_data);
            try base.validateConfig(config);
            const self = try a.create(Self);
            self.* = .{ .allocator = a, .arena = .init(a), .native = native.*, .extension = extension, .config = config, .plan_id = pin.expected_id };
            errdefer self.deinit();
            const owned = self.arena.allocator();
            self.native.public_data.io_entries.input_words = try owned.dupe(u32, native.public_data.io_entries.input_words);
            self.native.public_data.io_entries.output_words = try owned.dupe(@import("../air/public_data.zig").OutputWord, native.public_data.io_entries.output_words);
            self.plan = try plans.Plan.init(owned, pin.plan.roots, pin.plan.memories, pin.plan.programs);
            const hashes = try Hashes.initVerifier(a, self.admission());
            self.hashes = hashes;
            try extension_mod.validate(&self.extension, &self.native, self.admission(), hashes.logs);
            var temporary = std.heap.ArenaAllocator.init(a);
            defer temporary.deinit();
            const scratch = temporary.allocator();
            var pp: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            try base.nativePreprocessedWithExternal(scratch, &self.native, extension.counts.external_retirements, &pp);
            try pp.appendSlice(scratch, hashes.preprocessed());
            try pp.appendSlice(scratch, try @import("guest_precompile/ethereum_preprocessed.zig").generateExtension(scratch, &extension));
            const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
            var scheme = try Scheme.init(a, config);
            defer scheme.deinit(a);
            var channel = suite.Channel{};
            try scheme.commit(a, pp.items, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            self.root = roots.items[0];
            self.id = try protocol.identity(config, &self.native, &self.extension, self.admission(), hashes.logs, self.root);
            self.logs[0] = try @import("../recursion/air/blake3_row_columns.zig").columnLogs(owned, pp.items);
            self.logs[1] = try self.columnLogs(owned, .main);
            self.logs[2] = try self.columnLogs(owned, .interaction);
            try hashes.releaseVerifierColumns();
            return self;
        }
        fn columnLogs(self: *const Self, a: std.mem.Allocator, comptime tree: base.ColumnTree) ![]u32 {
            const prefix = try base.columnLogsWithExternal(a, &self.native, self.hashes.?.logs, tree, self.extension.counts.external_retirements);
            defer a.free(prefix);
            var result: std.ArrayList(u32) = .empty;
            errdefer result.deinit(a);
            try result.appendSlice(a, prefix);
            for (self.extension.components) |descriptor| try result.appendNTimes(a, descriptor.log_size, if (tree == .main) descriptor.main_columns else descriptor.interaction_columns);
            return result.toOwnedSlice(a);
        }
        pub fn admission(self: *const Self) plans.Admission {
            return .{ .plan = &self.plan, .expected_id = self.plan_id };
        }
        pub fn validate(self: *const Self, expected: [32]u8) !void {
            const hashes = self.hashes orelse return error.InvalidPreparedExecution;
            if (!std.mem.eql(u8, &self.id, &expected) or !std.mem.eql(u8, &hashes.plan_id, &self.plan_id) or
                !std.mem.eql(u8, &try protocol.identity(self.config, &self.native, &self.extension, self.admission(), hashes.logs, self.root), &expected)) return error.UntrustedExecutionKey;
        }
        pub fn deinit(self: *Self) void {
            if (self.hashes) |hashes| hashes.deinit();
            self.arena.deinit();
            self.allocator.destroy(self);
        }
    };
}
