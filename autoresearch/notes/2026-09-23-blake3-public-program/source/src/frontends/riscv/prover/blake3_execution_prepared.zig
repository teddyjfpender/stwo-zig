//! Persistent verifier preparation. Owns the admitted statement and schedules;
//! releases fixed trace buffers after deriving their root. One verification at
//! a time per owner; independent owners may be scheduled in parallel.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const statement = @import("../air/statement.zig");
const plans = @import("blake3_commitment_plan.zig");
const Hashes = @import("blake3_commitment_columns.zig").Owner;
const Joined = @import("blake3_execution_components.zig").Owner;
const protocol = @import("blake3_execution_protocol.zig");
const Key = @import("blake3_execution_key.zig").Key;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        shape: statement.Blake3ExecutionStatement,
        plan: plans.Plan = undefined,
        plan_id: [32]u8,
        config: core.pcs.PcsConfig,
        hashes: ?*Hashes = null,
        key: Key = undefined,
        id: [32]u8 = undefined,
        logs: [3][]u32 = undefined,
        preflight: @import("interop_postcard").proof_preflight.Shape = undefined,
        pub fn init(a: std.mem.Allocator, source: *const statement.Blake3ExecutionStatement, pin: plans.Admission, config: core.pcs.PcsConfig) !*Self {
            try source.validateBlake3Execution();
            try pin.validatePublic(&source.public_data);
            try protocol.validateConfig(config);
            const self = try a.create(Self);
            self.* = .{ .allocator = a, .arena = std.heap.ArenaAllocator.init(a), .shape = source.*, .plan_id = pin.expected_id, .config = config };
            errdefer self.deinit();
            const owned = self.arena.allocator();
            self.shape.public_data.io_entries.input_words = try owned.dupe(u32, source.public_data.io_entries.input_words);
            self.shape.public_data.io_entries.output_words = try owned.dupe(@import("../air/public_data.zig").OutputWord, source.public_data.io_entries.output_words);
            self.plan = try plans.Plan.init(owned, pin.plan.roots, pin.plan.memories, pin.plan.programs, pin.plan.program_leaves);
            const owned_pin = self.admission();
            const hashes = try Hashes.initVerifier(a, owned_pin);
            self.hashes = hashes;
            var temporary = std.heap.ArenaAllocator.init(a);
            defer temporary.deinit();
            const scratch = temporary.allocator();
            var pp: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            try protocol.nativePreprocessed(scratch, &self.shape, &pp);
            try pp.appendSlice(scratch, hashes.preprocessed());
            const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
            var fixed = try Scheme.init(a, config);
            // Sampled openings can use the LDE; do not retain duplicate coefficients.
            fixed.setCoefficientRetentionPolicy(.never);
            defer fixed.deinit(a);
            var channel = suite.Channel{};
            try fixed.commitBorrowedStreaming(a, pp.items, 8, &channel);
            var roots = try fixed.roots(a);
            defer roots.deinit(a);
            self.key = .{ .preprocessed_root = roots.items[0], .hash_logs = hashes.logs };
            self.id = try self.key.identity(&self.shape, owned_pin, config);
            self.logs[0] = try @import("../recursion/air/blake3_row_columns.zig").columnLogs(owned, pp.items);
            self.logs[1] = try protocol.columnLogs(owned, &self.shape, hashes.logs, .main);
            self.logs[2] = try protocol.columnLogs(owned, &self.shape, hashes.logs, .interaction);
            const claims = try scratch.create(statement.RiscVInteractionClaim);
            claims.initZeroInto();
            claims.n_components = self.shape.n_components;
            claims.n_infra = self.shape.n_infra;
            const joined = try Joined.init(a, &self.shape, claims, @import("../recursion/air/universal_challenges.zig").UniversalRelations.dummy(), owned_pin);
            defer joined.deinit();
            try joined.bindCommitments(hashes, @splat(core.fields.qm31.QM31.zero()));
            var components: std.ArrayList(core.air.components.Component) = .empty;
            try components.appendSlice(scratch, joined.verifying.components.active());
            try components.appendSlice(scratch, &(try hashes.verifiers()));
            self.preflight = try @import("../recursion/detached_proof_preflight.zig").shapeForEncoding(scratch, .{ .components = components.items, .n_preprocessed_columns = self.logs[0].len }, config, @import("../recursion/artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES, 32, .raw_bytes);
            try hashes.releaseVerifierColumns();
            return self;
        }
        pub fn admission(self: *const Self) plans.Admission {
            return .{ .plan = &self.plan, .expected_id = self.plan_id };
        }
        pub fn validate(self: *const Self, expected: [32]u8) !void {
            if (!std.mem.eql(u8, &self.id, &expected)) return error.UntrustedExecutionKey;
            const hashes = self.hashes orelse return error.InvalidPreparedExecution;
            if (!std.mem.eql(u8, &hashes.plan_id, &self.plan_id) or !std.meta.eql(hashes.logs, self.key.hash_logs)) return error.InvalidPreparedExecution;
            try self.key.admit(&self.shape, self.admission(), self.config, expected);
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            if (self.hashes) |hashes| hashes.deinit();
            self.arena.deinit();
            a.destroy(self);
        }
    };
}
