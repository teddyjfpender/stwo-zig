//! Shared authenticated prepared key ownership for full-width extensions.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const native_mod = @import("../air/statement.zig");
const base = @import("blake3_execution_protocol.zig");
const plans = @import("blake3_commitment_plan.zig");
const Hashes = @import("blake3_commitment_columns.zig").Owner;
pub fn ForBackend(comptime Profile: type, comptime Backend: type) type {
    const extension_mod = Profile.admission;
    const protocol = Profile.protocol;
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
        ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan = null,
        range_components: ?*@import("compact_range_assembly.zig").Owner = null,
        root: [32]u8 = undefined,
        id: [32]u8 = undefined,
        logs: [3][]u32 = undefined,
        preflight: @import("interop_postcard").proof_preflight.Shape = undefined,
        pub fn init(a: std.mem.Allocator, native: *const native_mod.Blake3ExecutionStatement, extension: extension_mod.Statement, pin: plans.Admission, config: core.pcs.PcsConfig) !*Self {
            return initMode(a, native, extension, pin, config, null);
        }
        pub fn initCompact(a: std.mem.Allocator, native: *const native_mod.Blake3ExecutionStatement, extension: extension_mod.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, ranges: @import("../recursion/air/compact_range_geometry.zig").Plan) !*Self {
            return initMode(a, native, extension, pin, config, ranges);
        }
        fn initMode(a: std.mem.Allocator, native: *const native_mod.Blake3ExecutionStatement, extension: extension_mod.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan) !*Self {
            try native.validateBlake3ExecutionWithExternal(Profile.externalCount(&extension));
            if (ranges) |compact| try (@import("compact_execution_contract.zig").Contract{ .native = native, .ranges = compact }).validate(Profile.externalCount(&extension));
            try pin.validatePublic(&native.public_data);
            try base.validateConfig(config);
            const self = try a.create(Self);
            self.* = .{ .allocator = a, .arena = .init(a), .native = native.*, .extension = extension, .config = config, .plan_id = pin.expected_id, .ranges = ranges };
            errdefer self.deinit();
            const owned = self.arena.allocator();
            self.native.public_data.io_entries.input_words = try owned.dupe(u32, native.public_data.io_entries.input_words);
            self.native.public_data.io_entries.output_words = try owned.dupe(@import("../air/public_data.zig").OutputWord, native.public_data.io_entries.output_words);
            self.plan = try plans.Plan.init(owned, pin.plan.roots, pin.plan.memories, pin.plan.programs, pin.plan.program_leaves);
            const hashes = try Hashes.initVerifier(a, self.admission());
            self.hashes = hashes;
            try extension_mod.validate(&self.extension, &self.native, self.admission(), hashes.logs);
            var temporary = std.heap.ArenaAllocator.init(a);
            defer temporary.deinit();
            const scratch = temporary.allocator();
            var pp: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            try base.nativePreprocessedWithExternal(scratch, &self.native, Profile.externalCount(&extension), &pp);
            try pp.appendSlice(scratch, hashes.preprocessed());
            try pp.appendSlice(scratch, try Profile.preprocessed(scratch, &extension));
            const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
            var scheme = try Scheme.init(a, config);
            // Sampled openings can use the LDE; do not retain duplicate coefficients.
            scheme.setCoefficientRetentionPolicy(.never);
            defer scheme.deinit(a);
            var channel = suite.Channel{};
            try scheme.commitBorrowedStreaming(a, pp.items, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            self.root = roots.items[0];
            self.id = try self.identity();
            self.logs[0] = try @import("../recursion/air/blake3_row_columns.zig").columnLogs(owned, pp.items);
            self.logs[1] = try self.columnLogs(owned, .main);
            self.logs[2] = try self.columnLogs(owned, .interaction);
            const claims = try scratch.create(native_mod.RiscVInteractionClaim);
            claims.initZeroInto();
            claims.n_components = self.native.n_components;
            claims.n_infra = self.native.n_infra;
            const universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations.dummy();
            const providers = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
            const relations = try Profile.Relations.fromDraws(providers.native, &@as([Profile.draw_count]core.fields.qm31.QM31, @splat(core.fields.qm31.QM31.one())));
            const joined = try @import("blake3_execution_components.zig").Owner.initWithExternal(a, &self.native, claims, universal, self.admission(), Profile.externalCount(&self.extension));
            defer joined.deinit();
            if (ranges) |compact| {
                self.range_components = try @import("compact_range_assembly.zig").Owner.init(a, compact, try compact.identity(), .{ .columns = joined.origin.columns, .claimed_sum_index = joined.origin.claimed_sum_index }, false);
                try joined.bindCompactCommitments(hashes, @splat(core.fields.qm31.QM31.zero()), self.range_components.?, @splat(core.fields.qm31.QM31.zero()));
            } else try joined.bindCommitments(hashes, @splat(core.fields.qm31.QM31.zero()));
            const extension_claim = try Profile.ExtensionClaim.zeroForStatement(&self.extension);
            var prefix: std.ArrayList(core.air.components.Component) = .empty;
            try prefix.appendSlice(scratch, joined.verifying.components.active());
            try prefix.appendSlice(scratch, &(try hashes.verifiers()));
            const components = try Profile.Assembly(.verifier).createBlake3WithRanges(a, &self.native, &self.extension, self.admission(), hashes.logs, &relations, prefix.items, &extension_claim, self.ranges);
            defer components.destroy(a);
            self.preflight = try @import("../recursion/detached_proof_preflight.zig").shapeForEncoding(scratch, .{ .components = components.active(), .n_preprocessed_columns = self.logs[0].len }, config, @import("../recursion/artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES, 32, .raw_bytes);
            try hashes.releaseVerifierColumns();
            return self;
        }
        fn columnLogs(self: *const Self, a: std.mem.Allocator, comptime tree: base.ColumnTree) ![]u32 {
            const prefix = if (self.ranges) |compact| try (@import("compact_execution_contract.zig").Contract{ .native = &self.native, .ranges = compact }).columnLogs(a, self.hashes.?.logs, tree, Profile.externalCount(&self.extension)) else try base.columnLogsWithExternal(a, &self.native, self.hashes.?.logs, tree, Profile.externalCount(&self.extension));
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
        fn identity(self: *const Self) ![32]u8 {
            if (self.ranges) |compact| return (@import("compact_extension_contract.zig").ForProfile(Profile){ .native = &self.native, .extension = &self.extension, .ranges = compact }).identity(self.config, self.admission(), self.hashes.?.logs, self.root);
            return protocol.identity(self.config, &self.native, &self.extension, self.admission(), self.hashes.?.logs, self.root);
        }
        pub fn validate(self: *const Self, expected: [32]u8) !void {
            const hashes = self.hashes orelse return error.InvalidPreparedExecution;
            if (!std.mem.eql(u8, &self.id, &expected) or !std.mem.eql(u8, &hashes.plan_id, &self.plan_id) or
                !std.mem.eql(u8, &try self.identity(), &expected)) return error.UntrustedExecutionKey;
        }
        pub fn deinit(self: *Self) void {
            if (self.range_components) |ranges| ranges.deinit();
            if (self.hashes) |hashes| hashes.deinit();
            self.arena.deinit();
            self.allocator.destroy(self);
        }
    };
}
