const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const work_pool = @import("stwo_prover_engine").work_pool;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
const support = frontend.testing.guest_precompile_main_trace_support;
const guest_statement = frontend.air.guest_precompile.statement;
const component_registry = frontend.air.guest_precompile.component_registry;
const aggregation_fixture = frontend.testing.aggregation_test_fixture;
const aggregation_types = frontend.testing.aggregation_types;
const production = frontend.prover_mod.main_trace_plan_execution_production;
const split_leaf_prepare = frontend.testing.split_leaf_prepare;
const split_leaf_statement = frontend.testing.split_leaf_statement;
const subject = frontend.prover_mod.guest_precompile.split_pcs_prepare;
const caller_finish = frontend.prover_mod.guest_precompile.split_caller_finish;
const provider_finish = frontend.prover_mod.guest_precompile.split_provider_finish;
const commitment_witness = frontend.testing.commitment_witness;
const statement_geometry = frontend.testing.statement_geometry;
const proof_workspace = frontend.testing.proof_workspace;
const main_trace_plan = frontend.testing.main_trace_plan;
const runner = frontend.runner;
const public_data_mod = frontend.air.public_data;

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

pub const Authorities = struct {
    accepted: aggregation_types.AcceptedProtocolV1,
    caller: split_leaf_prepare.CallerPrepareAuthorityV1,
    provider: split_leaf_prepare.ProviderPrepareAuthorityV1,
};

pub const OwnedPublicData = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data_mod.OutputWord,
    value: public_data_mod.PublicData,

    pub fn init(
        allocator: std.mem.Allocator,
        run: *const runner.Poseidon2RunResult,
    ) !OwnedPublicData {
        const input_words = try public_data_mod.packInputWords(
            allocator,
            run.base.input,
        );
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data_mod.OutputWord,
            run.base.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, run.base.output_words) |*destination, source| {
            destination.* = .{
                .addr = source.addr,
                .value = source.value,
                .clock = source.clock,
            };
        }
        return .{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = .{
                .initial_pc = run.base.initial_pc,
                .final_pc = run.base.final_pc,
                .clock = @intCast(run.base.step_count),
                .initial_regs = run.base.initial_regs,
                .final_regs = run.base.final_regs,
                .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
                .program_root = null,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = try public_data_mod.completionFromRun(run.base),
                .io_entries = .{
                    .input_start = run.base.input_start,
                    .input_len = @intCast(run.base.input.len),
                    .input_words = input_words,
                    .output_len = run.base.output_len,
                    .output_len_addr = run.base.output_len_addr,
                    .output_data_addr = run.base.output_data_addr,
                    .output_words = output_words,
                },
            },
        };
    }

    pub fn deinit(self: *OwnedPublicData) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};

pub fn authorities(call_count: u32) !Authorities {
    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = aggregation_fixture.digest(0xa1),
        .relation_registry_digest = aggregation_fixture.digest(0xa2),
    };
    return .{
        .accepted = accepted,
        .caller = try split_leaf_prepare.CallerPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(0x18),
            aggregation_fixture.digest(0xc1),
            call_count,
        ),
        .provider = try split_leaf_prepare.ProviderPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(0x18),
            aggregation_fixture.digest(0xc2),
            call_count,
        ),
    };
}

pub const BaseOwner = struct {
    allocator: std.mem.Allocator,
    value: production.MainCommitment,

    pub fn init(
        allocator: std.mem.Allocator,
        core: anytype,
        marker: u32,
    ) !BaseOwner {
        return initColumnCount(allocator, core, marker, core.nMainColumns());
    }

    pub fn initIncomplete(
        allocator: std.mem.Allocator,
        core: anytype,
        marker: u32,
    ) !BaseOwner {
        if (core.nMainColumns() == 0) return error.EmptyBaseMainGeometry;
        return initColumnCount(
            allocator,
            core,
            marker,
            core.nMainColumns() - 1,
        );
    }

    pub fn initColumnCount(
        allocator: std.mem.Allocator,
        core: anytype,
        marker: u32,
        column_count: usize,
    ) !BaseOwner {
        const columns = try allocator.alloc(ColumnEvaluation, column_count);
        var initialized: usize = 0;
        errdefer {
            for (columns[0..initialized]) |column| allocator.free(column.values);
            allocator.free(columns);
        }
        var cursor: usize = 0;
        for (core.component_descs[0..core.n_components]) |descriptor| {
            try appendColumns(
                allocator,
                columns,
                &cursor,
                descriptor.log_size,
                descriptor.n_columns,
                marker,
            );
            initialized = cursor;
        }
        for (core.infra_descs[0..core.n_infra]) |descriptor| {
            try appendColumns(
                allocator,
                columns,
                &cursor,
                descriptor.log_size,
                descriptor.n_columns,
                marker,
            );
            initialized = cursor;
        }
        std.debug.assert(cursor == columns.len);
        return .{
            .allocator = allocator,
            .value = .{
                .destination_policy = .independent_columns,
                .columns = columns,
                .backing = null,
            },
        };
    }

    pub fn deinit(self: *BaseOwner) void {
        self.value.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn appendColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    cursor: *usize,
    log_size: u32,
    count_u32: u32,
    marker: u32,
) !void {
    const domain = @as(usize, 1) << @intCast(log_size);
    const count: usize = @min(@as(usize, count_u32), columns.len - cursor.*);
    for (0..count) |_| {
        const values = try allocator.alloc(M31, domain);
        for (values, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(
                (marker +% @as(u32, @intCast(cursor.* * 131 + row))) %
                    (0x7fff_ffff - 1),
            ));
        }
        columns[cursor.*] = .{ .log_size = log_size, .values = values };
        cursor.* += 1;
    }
}

pub const Pair = struct {
    caller: subject.PreparedCallerPcsV1(Engine),
    provider: subject.PreparedProviderPcsV1(Engine),

    pub fn deinit(self: *Pair) void {
        self.provider.deinit();
        self.caller.deinit();
        self.* = undefined;
    }
};

pub fn preparePair(
    allocator: std.mem.Allocator,
    count: usize,
    reverse_order: bool,
) !Pair {
    var core = support.coreFixture(@intCast(count));
    const extension = try guest_statement.ExtensionStatement.canonical(
        &core,
        @intCast(count),
    );
    var logs = try support.logsFixture(allocator, count);
    defer logs.deinit();
    const authority = try authorities(@intCast(count));

    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var provider_shadow = try split_leaf_prepare.prepareProvider(
        allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var base = try BaseOwner.init(allocator, &core, 0x1020_3040);

    if (reverse_order) {
        var provider = try subject.prepareProvider(
            Engine,
            allocator,
            test_config,
            &core,
            &extension,
            &provider_shadow,
            null,
        );
        errdefer provider.deinit();
        const caller = try subject.prepareCaller(
            Engine,
            allocator,
            test_config,
            &core,
            &extension,
            &base.value,
            &caller_shadow,
            null,
        );
        return .{ .caller = caller, .provider = provider };
    }

    var caller = try subject.prepareCaller(
        Engine,
        allocator,
        test_config,
        &core,
        &extension,
        &base.value,
        &caller_shadow,
        null,
    );
    errdefer caller.deinit();
    const provider = try subject.prepareProvider(
        Engine,
        allocator,
        test_config,
        &core,
        &extension,
        &provider_shadow,
        null,
    );
    return .{ .caller = caller, .provider = provider };
}

pub fn identities(
    comptime role: aggregation_types.LeafRole,
    prepared: anytype,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = role,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.roots[subject.tree0_index],
            .component = prepared.authority.component,
        },
    };
}

pub const ParallelReceipt = struct {
    role: aggregation_types.LeafRole,
    roots: [subject.tree_count]subject.Digest = undefined,
    channel_digest: subject.Digest = undefined,
    failure: ?anyerror = null,
    allocator_leaked: bool = false,

    pub fn run(self: *ParallelReceipt) void {
        // Each role owns an allocator and all PCS state below it. The workers
        // share no mutable proving state and publish only fixed-size receipts
        // after their retained schemes have been destroyed.
        var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
        self.prepare(gpa.allocator()) catch |err| {
            self.failure = err;
        };
        self.allocator_leaked = gpa.deinit() == .leak;
    }

    pub fn prepare(self: *ParallelReceipt, allocator: std.mem.Allocator) !void {
        const count: usize = 1;
        var core = support.coreFixture(@intCast(count));
        const extension = try guest_statement.ExtensionStatement.canonical(
            &core,
            @intCast(count),
        );
        var logs = try support.logsFixture(allocator, count);
        defer logs.deinit();
        const authority = try authorities(@intCast(count));

        switch (self.role) {
            .core_request => {
                var shadow = try split_leaf_prepare.prepareCaller(
                    allocator,
                    authority.caller,
                    &core,
                    &extension,
                    &logs.calls,
                    &logs.rows,
                );
                var shadow_owned = true;
                defer if (shadow_owned) shadow.deinit();
                var base = try BaseOwner.init(allocator, &core, 0x1020_3040);
                var base_owned = true;
                defer if (base_owned) base.deinit();
                shadow_owned = false;
                base_owned = false;
                var prepared = try subject.prepareCaller(
                    Engine,
                    allocator,
                    test_config,
                    &core,
                    &extension,
                    &base.value,
                    &shadow,
                    null,
                );
                defer prepared.deinit();
                self.roots = prepared.roots;
                self.channel_digest = prepared.channel.digestBytes();
            },
            .poseidon2_provider => {
                var shadow = try split_leaf_prepare.prepareProvider(
                    allocator,
                    authority.provider,
                    &core,
                    &extension,
                    &logs.calls,
                    &logs.rows,
                );
                var shadow_owned = true;
                defer if (shadow_owned) shadow.deinit();
                shadow_owned = false;
                var prepared = try subject.prepareProvider(
                    Engine,
                    allocator,
                    test_config,
                    &core,
                    &extension,
                    &shadow,
                    null,
                );
                defer prepared.deinit();
                self.roots = prepared.roots;
                self.channel_digest = prepared.channel.digestBytes();
            },
        }
    }
};
