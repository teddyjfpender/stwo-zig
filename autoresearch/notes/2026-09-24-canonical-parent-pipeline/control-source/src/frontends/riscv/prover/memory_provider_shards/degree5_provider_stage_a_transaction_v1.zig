//! Process-local Stage-A custody for one degree-five Poseidon provider shard.
//!
//! The ordinary provider path historically materialized and committed the
//! selector/main trees once to mint the shared Stage-A manifest, destroyed
//! that prover, and then repeated the same work for the shard proof. This
//! owner retains the first, coefficient-bearing commitment scheme and moves it
//! exactly once into the proof after the final shared manifest has been
//! validated. It has no codec and pointer identity is part of its admission.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;

const aggregation_hash = @import("../../aggregation/hash.zig");
const candidate_mod = @import("../../air/lang/typed_poseidon2_degree_bounded_candidate.zig");
const trace_mod = @import("../../air/lang/typed_poseidon2_degree5_trace.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const binding = @import("degree5_ethereum_omit_provider_authority_v1.zig");
const component_mod = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const harness = @import("proof_harness.zig");

pub const format_version: u32 = 1;

pub const ReuseReceiptV1 = struct {
    format: u32 = format_version,
    shard_index: u32,
    log_size: u32,
    call_count: u32,
    selector_materializations: u8 = 1,
    main_materializations: u8 = 1,
    stage_a_commit_transactions: u8 = 1,
    scheme_moves: u8 = 0,
    duplicate_stage_a_transactions_avoided: u8 = 0,

    pub fn validate(self: ReuseReceiptV1, consumed: bool) !void {
        const expected_moves: u8 = @intFromBool(consumed);
        if (self.format != format_version or self.call_count == 0 or
            self.selector_materializations != 1 or
            self.main_materializations != 1 or
            self.stage_a_commit_transactions != 1 or
            self.scheme_moves != expected_moves or
            self.duplicate_stage_a_transactions_avoided != expected_moves)
        {
            return error.InvalidDegree5StageAReuseReceipt;
        }
    }
};

pub fn PreparedStageATransactionV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        candidate: candidate_mod.Candidate,
        scheme: Engine.Scheme,
        plan: *const authority.ProviderShardPlanV1,
        validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
        calls_ptr: [*]const poseidon2_air.Call,
        calls_len: usize,
        program_identity: aggregation_hash.Digest,
        descriptor_identity: aggregation_hash.Digest,
        roots_value: harness.StageACommitment(Engine),
        receipt: ReuseReceiptV1,
        scheme_live: bool = true,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            pcs_config: core_pcs.PcsConfig,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            shard_index: u32,
        ) !Self {
            return initInternal(
                allocator,
                pcs_config,
                expected_program,
                plan,
                calls,
                shard_index,
                null,
            );
        }

        pub fn initValidated(
            allocator: std.mem.Allocator,
            pcs_config: core_pcs.PcsConfig,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: *const authority.OwnedValidatedPlanCallAuthorityV1,
            shard_index: u32,
        ) !Self {
            return initInternal(
                allocator,
                pcs_config,
                expected_program,
                plan,
                calls,
                shard_index,
                validated_calls,
            );
        }

        fn initInternal(
            allocator: std.mem.Allocator,
            pcs_config: core_pcs.PcsConfig,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            shard_index: u32,
            validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
        ) !Self {
            const shard_calls = if (validated_calls) |validated|
                try harness.admittedShardValidated(
                    validated,
                    plan,
                    calls,
                    shard_index,
                )
            else
                try harness.admittedShard(plan, calls, shard_index);
            const index = std.math.cast(usize, shard_index) orelse
                return error.ShardIndexOutOfRange;
            const descriptor = plan.shards[index];

            var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
            errdefer candidate.deinit();
            try expected_program.validateCandidate(&candidate);

            var channel = Engine.Channel{};
            pcs_config.mixInto(&channel);
            var scheme = try Engine.init(allocator, pcs_config);
            errdefer Engine.deinit(&scheme, allocator);
            scheme.setCoefficientRetentionPolicy(.always);
            try commitStageAInto(
                Engine,
                allocator,
                &scheme,
                &channel,
                &candidate,
                shard_calls,
                descriptor,
            );
            try Engine.flushPendingCommit(&scheme, allocator, &channel);
            const roots_value = try currentRoots(Engine, allocator, &scheme);

            var result = Self{
                .allocator = allocator,
                .candidate = candidate,
                .scheme = scheme,
                .plan = plan,
                .validated_calls = validated_calls,
                .calls_ptr = calls.ptr,
                .calls_len = calls.len,
                .program_identity = expected_program.air_program_identity,
                .descriptor_identity = descriptor.identity,
                .roots_value = roots_value,
                .receipt = .{
                    .shard_index = shard_index,
                    .log_size = descriptor.expected_log_size,
                    .call_count = descriptor.call_count,
                },
            };
            try result.validateBorrowedInternal(
                expected_program,
                plan,
                calls,
                validated_calls,
                shard_index,
                roots_value.preprocessed_root,
                roots_value.main_root,
            );
            return result;
        }

        pub fn roots(self: *const Self) !harness.StageACommitment(Engine) {
            try self.receipt.validate(!self.scheme_live);
            return self.roots_value;
        }

        pub fn validateBorrowed(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !void {
            return self.validateBorrowedInternal(
                expected_program,
                plan,
                calls,
                null,
                shard_index,
                expected_preprocessed_root,
                expected_main_root,
            );
        }

        pub fn validateBorrowedValidated(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: *const authority.OwnedValidatedPlanCallAuthorityV1,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !void {
            return self.validateBorrowedInternal(
                expected_program,
                plan,
                calls,
                validated_calls,
                shard_index,
                expected_preprocessed_root,
                expected_main_root,
            );
        }

        fn validateBorrowedInternal(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !void {
            if (!self.scheme_live) return error.Degree5StageATransactionConsumed;
            try expected_program.validateCandidate(&self.candidate);
            const index = std.math.cast(usize, shard_index) orelse
                return error.ShardIndexOutOfRange;
            if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
            const descriptor = plan.shards[index];
            if (self.plan != plan or self.validated_calls != validated_calls or
                self.calls_ptr != calls.ptr or
                self.calls_len != calls.len or self.receipt.shard_index != shard_index or
                !aggregation_hash.eql(
                    self.program_identity,
                    expected_program.air_program_identity,
                ) or !aggregation_hash.eql(
                self.descriptor_identity,
                descriptor.identity,
            )) {
                return error.InvalidDegree5StageABorrowedAuthority;
            }
            const shard_calls = if (validated_calls) |validated|
                try harness.admittedShardValidated(
                    validated,
                    plan,
                    calls,
                    shard_index,
                )
            else
                try harness.admittedShard(plan, calls, shard_index);
            if (shard_calls.ptr != calls[@intCast(descriptor.first_call)..].ptr or
                shard_calls.len != descriptor.call_count)
            {
                return error.InvalidDegree5StageABorrowedAuthority;
            }
            try self.receipt.validate(false);
            const observed = try currentRoots(Engine, self.allocator, &self.scheme);
            if (!std.meta.eql(observed, self.roots_value) or
                !std.meta.eql(observed.preprocessed_root, expected_preprocessed_root) or
                !std.meta.eql(observed.main_root, expected_main_root))
            {
                return error.Degree5StageARootMismatch;
            }
        }

        /// Moves the only live commitment scheme into the provider proof.
        /// The candidate graph remains borrowed from this owner until proving
        /// returns; callers must therefore keep the transaction live.
        pub fn takeScheme(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !Engine.Scheme {
            return self.takeSchemeInternal(
                expected_program,
                plan,
                calls,
                null,
                shard_index,
                expected_preprocessed_root,
                expected_main_root,
            );
        }

        pub fn takeSchemeValidated(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: *const authority.OwnedValidatedPlanCallAuthorityV1,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !Engine.Scheme {
            return self.takeSchemeInternal(
                expected_program,
                plan,
                calls,
                validated_calls,
                shard_index,
                expected_preprocessed_root,
                expected_main_root,
            );
        }

        fn takeSchemeInternal(
            self: *Self,
            expected_program: binding.VerifierProgramAuthorityV2,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
            shard_index: u32,
            expected_preprocessed_root: Engine.Hasher.Hash,
            expected_main_root: Engine.Hasher.Hash,
        ) !Engine.Scheme {
            try self.validateBorrowedInternal(
                expected_program,
                plan,
                calls,
                validated_calls,
                shard_index,
                expected_preprocessed_root,
                expected_main_root,
            );
            const scheme = self.scheme;
            self.scheme = undefined;
            self.scheme_live = false;
            self.receipt.scheme_moves = 1;
            self.receipt.duplicate_stage_a_transactions_avoided = 1;
            try self.receipt.validate(true);
            return scheme;
        }

        pub fn validateConsumed(self: *const Self) !void {
            if (self.scheme_live) return error.Degree5StageATransactionNotConsumed;
            try self.receipt.validate(true);
        }

        pub fn deinit(self: *Self) void {
            if (self.scheme_live) Engine.deinit(&self.scheme, self.allocator);
            self.candidate.deinit();
            self.* = undefined;
        }
    };
}

pub fn commitStageAInto(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    candidate: *const candidate_mod.Candidate,
    calls: []const poseidon2_air.Call,
    descriptor: authority.ProviderShardDescriptorV1,
) !void {
    try Engine.commit(
        scheme,
        allocator,
        try harness.generateSelectors(
            allocator,
            descriptor.expected_log_size,
            descriptor.call_count,
        ),
        null,
        channel,
    );
    var main = try trace_mod.generateMain(
        allocator,
        candidate,
        calls,
        descriptor.expected_log_size,
    );
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const columns = try wrapColumns(
        allocator,
        main.values,
        descriptor.expected_log_size,
    );
    allocator.free(main.values);
    main_owned = false;
    try Engine.commit(scheme, allocator, columns, null, channel);
}

fn currentRoots(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
) !harness.StageACommitment(Engine) {
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2) return error.InvalidDegree5ProviderStageATrees;
    return .{
        .preprocessed_root = roots.items[0],
        .main_root = roots.items[1],
    };
}

fn wrapColumns(
    allocator: std.mem.Allocator,
    values: [][]M31,
    log_size: u32,
) ![]prover_pcs.ColumnEvaluation {
    if (values.len != component_mod.MAIN_COLUMNS)
        return error.InvalidDegree5ProviderMainColumns;
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, values.len);
    for (columns, values) |*column, source|
        column.* = .{ .log_size = log_size, .values = source };
    return columns;
}

comptime {
    if (component_mod.MAIN_COLUMNS != 239)
        @compileError("degree-five retained Stage-A geometry drifted");
}
