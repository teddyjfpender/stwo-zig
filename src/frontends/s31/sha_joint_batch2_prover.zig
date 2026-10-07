//! One PCS/FRI proof for a sparse-wide S31 circuit and six packed SHA-256
//! compression calls. Two caller AIRs independently connect each private
//! header/digest boundary to the circuit Gate and SHA recursion-wire buses.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cairo = @import("stwo_cairo_frontend");
const sha = @import("s31_sha_provider");
const plan_mod = @import("sha_chip_plan.zig");
const equations = @import("sha_caller_equations.zig");
const caller = @import("sha_caller_air.zig");
const profile_mod = @import("sha_joint_batch2_profile.zig");
const envelope = @import("sha_joint_batch2_envelope.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const Channel = MC.Channel;
const Engine = cpu.prove.Internal.Engine;
const Column = engine.pcs.ColumnEvaluation;
const sparse_pp = circuit.common.sparse_wide;
const sparse_trace = circuit.witness.sparse_wide;
const Airs = .{ sha.Source, sha.Schedule, sha.Round, sha.FeedForward };
const names = [_][:0]const u8{ "sha_source", "sha_schedule", "sha_round", "sha_feed_forward" };
const Roster = sha.component_roster.ForAirs(Airs, &names);
const kinds = sha.joint_lookup_kinds;
const circuit_component_count = sparse_pp.active_component_indices.len;
const sha_component_count = Airs.len;
const table_count = kinds.len;
const total_component_count = circuit_component_count + sha_component_count + profile_mod.caller_component_count + table_count;
const claim_count = total_component_count + profile_mod.caller_component_count;

pub const Request = struct {
    source_digest: [32]u8,
    /// Compiler-sealed builder variable count and addresses, not proof data.
    n_vars: u32,
    gate_addresses: [profile_mod.header_count][equations.gate_limb_count]u32,
    /// Private witnesses used to prepare six SHA calls. The two caller AIRs
    /// and Gate/recursion-wire LogUps, not host values, grant authority.
    headers: [profile_mod.header_count][80]u8,
    /// Adversarial harness only; changes are committed before challenges.
    test_mutation: ?TestMutation = null,
    /// Diagnostic output; timings never enter the transcript or proof bytes.
    metrics: ?*Metrics = null,
};

pub const TestMutation = enum {
    header_and_sha_input,
    digest_and_sha_output,
    second_header_and_sha_input,
    second_digest_and_sha_output,
};

pub const Metrics = struct {
    setup_ns: u64 = 0,
    fixed_commit_ns: u64 = 0,
    main_witness_ns: u64 = 0,
    main_commit_ns: u64 = 0,
    interaction_witness_ns: u64 = 0,
    interaction_commit_ns: u64 = 0,
    component_bind_ns: u64 = 0,
    fri_ns: u64 = 0,
    fri_pow_ns: u64 = 0,
    fixed_columns: usize = 0,
    main_columns: usize = 0,
    interaction_columns: usize = 0,
    table_nonzero_rows: [table_count]usize = @splat(0),
};

pub const Proof = struct {
    allocator: std.mem.Allocator,
    profile: profile_mod.Profile,
    preprocessed_root: [32]u8,
    key_digest: [32]u8,
    circuit_identity: [32]u8,
    output_values: []QM31,
    interaction_pow_nonce: u64,
    /// Circuit Eq/QM31/M31-to-u32/range16, SHA source/schedule/round/feed,
    /// two caller Gate/wire pairs, then two lookup tables.
    claimed_sums: [claim_count]QM31,
    stark_proof: core.proof.ExtendedStarkProof(MC.MerkleHasher),

    pub fn deinit(self: *Proof) void {
        self.stark_proof.deinit(self.allocator);
        self.allocator.free(self.output_values);
        self.* = undefined;
    }
};

pub fn serialize(allocator: std.mem.Allocator, proof: *const Proof) ![]u8 {
    if (!std.mem.eql(u8, &proof.key_digest, &(try proof.profile.keyDigest(proof.preprocessed_root))) or
        !std.mem.eql(u8, &proof.circuit_identity, &(try proof.profile.circuitIdentity(proof.preprocessed_root))))
        return error.InvalidShaJointProofKey;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    const header = try envelope.encodeHeader(
        proof.profile,
        proof.preprocessed_root,
        proof.interaction_pow_nonce,
        proof.claimed_sums,
    );
    try bytes.appendSlice(allocator, &header);
    try postcard.serializeProof(MC.MerkleHasher, bytes.writer(allocator), proof.stark_proof.proof);
    return bytes.toOwnedSlice(allocator);
}

/// The proof object contains one commitment forest and one FRI opening.
pub fn prove(
    allocator: std.mem.Allocator,
    values: []const QM31,
    pp: *const sparse_pp.Circuit,
    template: *const cpu.air.Bundle,
    pcs: core.pcs.config_v2.PcsConfigV2,
    request: Request,
) !Proof {
    var stage_timer = try std.time.Timer.start();
    const boundary = pp.sha_boundary_pair orelse return error.MissingShaBoundaryPair;
    if (!std.meta.eql(boundary.first.addresses, request.gate_addresses[0]) or
        !std.meta.eql(boundary.second.addresses, request.gate_addresses[1]) or
        @as(usize, request.n_vars) != values.len) return error.InvalidShaBoundaryKey;
    const layout = pp.layout();
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    var circuit_base = try sparse_trace.writeBase(a, values, pp);
    defer circuit_base.deinit();
    if (circuit_base.output_values.len != profile_mod.public_output_count)
        return error.InvalidShaJointPublicOutputCount;
    const profile = try profile_mod.Profile.canonical(
        request.source_digest,
        circuit_base.log_sizes,
        request.n_vars,
        request.gate_addresses,
        pcs,
    );
    try profile.validate();

    const plan0 = plan_mod.prepare(request.headers[0]);
    const plan1 = plan_mod.prepare(request.headers[1]);
    const calls0 = try plan_mod.providerCalls(request.headers[0], plan0, 1);
    const calls1 = try plan_mod.providerCalls(request.headers[1], plan1, 4);
    const calls = calls0 ++ calls1;
    var prepared = try sha.prepare(a, &calls);
    defer prepared.deinit();
    const caller_row0 = try equations.witness(request.headers[0], plan0);
    const caller_row1 = try equations.witness(request.headers[1], plan1);
    const caller_config0 = caller.Config{ .gate_addresses = request.gate_addresses[0], .first_call_id = 1 };
    const caller_config1 = caller.Config{ .gate_addresses = request.gate_addresses[1], .first_call_id = 4 };

    var fixed: std.ArrayList(Column) = .empty;
    var main: std.ArrayList(Column) = .empty;
    var interaction: std.ArrayList(Column) = .empty;
    for (pp.columns) |column| try fixed.append(a, .{ .log_size = column.logSize(), .values = column.values });
    try sha.preprocessed.append(a, calls.len, false, &fixed);
    var table_fixed: [table_count]usize = undefined;
    for (kinds, &table_fixed) |kind, *offset| {
        offset.* = fixed.items.len;
        try sha.row_columns.tablePreprocessed(a, kind, &fixed);
    }
    if (request.metrics) |metrics| {
        metrics.setup_ns = stage_timer.lap();
        metrics.fixed_columns = fixed.items.len;
    }

    var channel = Channel{};
    try profile.mixInto(&channel);
    core.channel.lookup_transcript.mixChannelSalt(&channel, 0);
    pcs.fri_config.mixInto(&channel);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.items, &channel);
    if (request.metrics) |metrics| metrics.fixed_commit_ns = stage_timer.lap();
    const fixed_root = scheme.trees.items[0].commitment.root();
    const key_digest = try profile.keyDigest(fixed_root);
    const circuit_identity = try profile.circuitIdentity(fixed_root);
    var bound = try cpu.air.bindSparseWide(a, template, circuit_base.log_sizes, &layout);
    defer bound.deinit();
    try main.appendSlice(a, circuit_base.columns);
    const rows = prepared.tuple();
    inline for (Airs, 0..) |Air, index|
        try sha.row_columns.project(Air, a, rows[index], prepared.geometry.logs[index], 1, &main);
    var caller_base0 = try caller.writeBase(a, caller_row0);
    defer caller_base0.deinit();
    var caller_base1 = try caller.writeBase(a, caller_row1);
    defer caller_base1.deinit();
    if (request.test_mutation) |mutation| switch (mutation) {
        .header_and_sha_input => {
            // Header limb 0 and the matching low byte of call 1 block word 0.
            // The caller's local limb equation remains zero.
            mutateCallerColumn(caller_base0.columns, 0);
            mutateCallerColumn(caller_base0.columns, 56 + 32 + 3);
        },
        .digest_and_sha_output => {
            // Digest limb 0 and the matching low byte of call 3 output word 0.
            mutateCallerColumn(caller_base0.columns, 40);
            mutateCallerColumn(caller_base0.columns, 56 + 2 * 128 + 32 + 64 + 3);
        },
        .second_header_and_sha_input => {
            mutateCallerColumn(caller_base1.columns, 0);
            mutateCallerColumn(caller_base1.columns, 56 + 32 + 3);
        },
        .second_digest_and_sha_output => {
            mutateCallerColumn(caller_base1.columns, 40);
            mutateCallerColumn(caller_base1.columns, 56 + 2 * 128 + 32 + 64 + 3);
        },
    };
    try main.appendSlice(a, caller_base0.columns);
    try main.appendSlice(a, caller_base1.columns);

    var definitions: Roster.Tuple(.definition) = undefined;
    var plans: Roster.Tuple(.plan) = undefined;
    var counters: [table_count]sha.Counter = undefined;
    for (&counters, kinds) |*counter, kind| counter.* = try sha.Counter.init(a, kind);
    inline for (Airs, 0..) |Air, i| {
        definitions[i] = try Air.build(a);
        plans[i] = try sha.binding.Binding(Air).authenticate(&definitions[i]);
        try registerTables(Air, &plans[i], rows[i], &counters);
    }
    for (&counters, 0..) |*counter, index| {
        var nonzero: usize = 0;
        for (counter.values) |value| nonzero += @intFromBool(!value.isZero());
        if (request.metrics) |metrics| metrics.table_nonzero_rows[index] = nonzero;
    }
    const table_main_offset = main.items.len;
    for (&counters, kinds) |*counter, kind|
        try main.append(a, .{ .log_size = sha.schema.logSize(kind), .values = try counter.committedColumn(a) });
    if (request.metrics) |metrics| {
        metrics.main_witness_ns = stage_timer.lap();
        metrics.main_columns = main.items.len;
    }
    MC.mixRoot(&channel, circuit_identity);
    channel.mixFelts(circuit_base.output_values);
    try commit(&scheme, allocator, main.items, &channel);
    if (request.metrics) |metrics| metrics.main_commit_ns = stage_timer.lap();

    const nonce = channel.grind(circuit.common.component_list.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(a, &channel);
    const vm_relations = try sha.universal.UniversalRelations.draw(a, &channel);
    const relations = try sha.sha_relations.draw(a, &channel, vm_relations);
    const providers = try sha.shared_provider_relations.SharedProviderRelations.init(&relations);

    var circuit_interaction = try sparse_trace.writeInteraction(
        a,
        &circuit_base,
        pp,
        gate_challenge.z,
        gate_challenge.alpha,
    );
    defer circuit_interaction.deinit();
    try interaction.appendSlice(a, circuit_interaction.columns);
    var claims: [claim_count]QM31 = undefined;
    @memcpy(claims[0..circuit_component_count], &circuit_interaction.claimed_sums);
    inline for (Airs, 0..) |Air, i| {
        const generated = try sha.framework.Runtime(sha.binding.Binding(Air).Runtime).generatePrepared(
            a,
            &plans[i],
            rows[i],
            prepared.geometry.logs[i],
            &relations,
        );
        claims[circuit_component_count + i] = generated.claimed_sum;
        for (generated.columns) |column|
            try interaction.append(a, .{ .log_size = prepared.geometry.logs[i], .values = column });
    }
    const caller_interaction_offset0 = interaction.items.len;
    var caller_interaction0 = try caller.writeInteraction(
        a,
        caller_base0.columns,
        caller_config0,
        caller.Elements.init(gate_challenge.z, gate_challenge.alpha),
        caller.Elements.init(relations.get(.recursion_wire).z, relations.get(.recursion_wire).alpha),
    );
    defer caller_interaction0.deinit();
    claims[circuit_component_count + sha_component_count] = caller_interaction0.gate_claimed_sum;
    claims[circuit_component_count + sha_component_count + 1] = caller_interaction0.sha_claimed_sum;
    try interaction.appendSlice(a, caller_interaction0.columns);
    const caller_interaction_offset1 = interaction.items.len;
    var caller_interaction1 = try caller.writeInteraction(
        a,
        caller_base1.columns,
        caller_config1,
        caller.Elements.init(gate_challenge.z, gate_challenge.alpha),
        caller.Elements.init(relations.get(.recursion_wire).z, relations.get(.recursion_wire).alpha),
    );
    defer caller_interaction1.deinit();
    claims[circuit_component_count + sha_component_count + 2] = caller_interaction1.gate_claimed_sum;
    claims[circuit_component_count + sha_component_count + 3] = caller_interaction1.sha_claimed_sum;
    try interaction.appendSlice(a, caller_interaction1.columns);
    const table_interaction_offset = interaction.items.len;
    for (&counters, kinds, 0..) |*counter, kind, i| {
        const generated = try sha.table_interaction.generate(a, counter, &providers.native);
        claims[circuit_component_count + sha_component_count + 4 + i] = generated.claim;
        for (generated.columns) |column|
            try interaction.append(a, .{ .log_size = sha.schema.logSize(kind), .values = column });
    }

    var sha_closure = caller_interaction0.sha_claimed_sum.add(caller_interaction1.sha_claimed_sum);
    for (claims[circuit_component_count..][0..sha_component_count]) |claim| sha_closure = sha_closure.add(claim);
    for (claims[circuit_component_count + sha_component_count + 4 ..]) |claim| sha_closure = sha_closure.add(claim);
    if (!sha_closure.isZero()) return error.InvalidJoinedShaWireLookupSum;
    const gate_closure = (try sparse_trace.lookupSum(
        circuit_base.output_values,
        circuit_interaction.claimed_sums,
        gate_challenge.z,
        gate_challenge.alpha,
    )).add(caller_interaction0.gate_claimed_sum).add(caller_interaction1.gate_claimed_sum);
    if (!gate_closure.isZero()) return error.InvalidJoinedShaGateLookupSum;
    if (request.metrics) |metrics| {
        metrics.interaction_witness_ns = stage_timer.lap();
        metrics.interaction_columns = interaction.items.len;
    }
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &claims);
    try commit(&scheme, allocator, interaction.items, &channel);
    if (request.metrics) |metrics| metrics.interaction_commit_ns = stage_timer.lap();

    var pp_logs: [sparse_pp.N_COLUMNS]u32 = undefined;
    for (layout.entries, &pp_logs) |entry, *log| log.* = entry.log_size;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured: [circuit_component_count]cairo.proving.air.component.Component = undefined;
    var handles: [total_component_count]engine.air.component_prover.ComponentProver = undefined;
    for (bound.components, &captured, handles[0..circuit_component_count], circuit_interaction.claimed_sums) |*source, *runtime, *handle, claim| {
        runtime.* = .init(a, source, &pp_logs, lifting_bound, gate_challenge.z, gate_challenge.alpha, claim);
        runtime.native_executor = null;
        handle.* = runtime.asProverComponent();
    }
    const roster_manifest = Roster.Manifest{
        .log_sizes = prepared.geometry.logs,
        .origin = .{ .columns = .{
            sparse_pp.N_COLUMNS,
            sparse_trace.main_width,
            sparse_trace.interaction_width,
            0,
        }, .claimed_sum_index = circuit_component_count },
    };
    const parameters: [sha_component_count][0]M31 = @splat(.{});
    const sha_owner = try sha.component_owner.ForRoster(Roster).initPrepared(
        a,
        &roster_manifest,
        &definitions,
        &plans,
        parameters,
        relations,
        claims[circuit_component_count..][0..sha_component_count].*,
    );
    defer sha_owner.deinit();
    @memcpy(handles[circuit_component_count..][0..sha_component_count], &(try sha_owner.proverHandles()));
    var caller_component0 = caller.Component{
        .main_offset = sparse_trace.main_width + shaMainWidth(),
        .interaction_offset = caller_interaction_offset0,
        .config = caller_config0,
        .gate_elements = caller.Elements.init(gate_challenge.z, gate_challenge.alpha),
        .wire_elements = caller.Elements.init(relations.get(.recursion_wire).z, relations.get(.recursion_wire).alpha),
        .gate_claimed_sum = caller_interaction0.gate_claimed_sum,
        .sha_claimed_sum = caller_interaction0.sha_claimed_sum,
    };
    handles[circuit_component_count + sha_component_count] = caller_component0.asProverComponent();
    var caller_component1 = caller.Component{
        .main_offset = sparse_trace.main_width + shaMainWidth() + caller.main_width,
        .interaction_offset = caller_interaction_offset1,
        .config = caller_config1,
        .gate_elements = caller.Elements.init(gate_challenge.z, gate_challenge.alpha),
        .wire_elements = caller.Elements.init(relations.get(.recursion_wire).z, relations.get(.recursion_wire).alpha),
        .gate_claimed_sum = caller_interaction1.gate_claimed_sum,
        .sha_claimed_sum = caller_interaction1.sha_claimed_sum,
    };
    handles[circuit_component_count + sha_component_count + 1] = caller_component1.asProverComponent();
    var tables: [table_count]sha.Table = undefined;
    for (&tables, kinds, table_fixed, 0..) |*table, kind, fixed_offset, i| {
        var indices: [sha.schema.MAX_ARITY]usize = undefined;
        for (indices[0..sha.schema.arity(kind)], 0..) |*slot, j| slot.* = fixed_offset + 1 + j;
        table.* = try sha.Table.initProver(
            kind,
            fixed_offset,
            indices[0..sha.schema.arity(kind)],
            table_main_offset + i,
            table_interaction_offset + 4 * i,
            &providers.native,
            claims[circuit_component_count + sha_component_count + 4 + i],
        );
        handles[circuit_component_count + sha_component_count + 2 + i] =
            try sha.component_geometry.ForAirs(Airs).table(table.asProverComponent());
    }
    if (request.metrics) |metrics| metrics.component_bind_ns = stage_timer.lap();
    var recorder = engine.stage_profile.Recorder.initWithOptions(allocator, "s31_sha_joint_batch2", "prove", .{ .capture_tasks = false });
    defer recorder.deinit();
    scheme_owned = false;
    var stark = try Engine.prove(allocator, &handles, &channel, scheme, .{
        .include_all_preprocessed_columns = true,
        .recorder = if (request.metrics != null) &recorder else null,
    });
    if (request.metrics) |metrics| {
        metrics.fri_ns = stage_timer.lap();
        var stage_profile = try recorder.snapshot(allocator);
        defer stage_profile.deinit(allocator);
        metrics.fri_pow_ns = @intFromFloat((findStageSeconds(stage_profile.stages, "proof_of_work") orelse 0) * std.time.ns_per_s);
        printStageTree(stage_profile.stages, 0);
    }
    errdefer stark.deinit(allocator);
    return .{
        .allocator = allocator,
        .profile = profile,
        .preprocessed_root = fixed_root,
        .key_digest = key_digest,
        .circuit_identity = circuit_identity,
        .output_values = try allocator.dupe(QM31, circuit_base.output_values),
        .interaction_pow_nonce = nonce,
        .claimed_sums = claims,
        .stark_proof = stark,
    };
}

fn shaMainWidth() usize {
    comptime var width: usize = 0;
    inline for (Airs) |Air| width += Air.PHYSICAL_MAIN_COLUMN_COUNT;
    return width;
}

fn mutateCallerColumn(columns: []const Column, index: usize) void {
    for (@constCast(columns[index].values)) |*value| value.* = value.add(M31.one());
}

fn findStageSeconds(nodes: []const engine.stage_profile.StageNode, id: []const u8) ?f64 {
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, id)) return node.seconds;
        if (node.children) |children| if (findStageSeconds(children, id)) |seconds| return seconds;
    }
    return null;
}

fn printStageTree(nodes: []const engine.stage_profile.StageNode, depth: usize) void {
    for (nodes) |node| {
        std.debug.print("S31_SHA_FRI_STAGE depth={d} id={s} ms={d:.2}\n", .{ depth, node.id, node.seconds * 1000 });
        if (node.children) |children| printStageTree(children, depth + 1);
    }
}

fn registerTables(comptime Air: type, plan: *const sha.binding.Binding(Air).Plan, rows: []const Air.Row, counters: *[table_count]sha.Counter) !void {
    const Visitor = struct {
        counters: *[table_count]sha.Counter,
        pub fn accepts(_: *@This(), id: anytype) bool {
            inline for (kinds) |kind|
                if (id == sha.relation.id(@field(sha.relation.Domain, @tagName(kind)))) return true;
            return false;
        }
        pub fn visit(self: *@This(), id: anytype, numerator: M31, tuple: []const M31) !void {
            inline for (kinds, 0..) |kind, i| if (id == sha.relation.id(@field(sha.relation.Domain, @tagName(kind)))) {
                try self.counters[i].registerBase(numerator, tuple);
                return;
            };
            return error.UnexpectedShaLookup;
        }
    };
    var visitor = Visitor{ .counters = counters };
    for (rows) |row| try plan.visitPreparedBaseEntries(row, &visitor);
}

fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *Channel) !void {
    const owned = try allocator.alloc(Column, columns.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |entry| allocator.free(entry.values);
        allocator.free(owned);
    }
    for (columns, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    try Engine.commit(scheme, allocator, owned, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}
