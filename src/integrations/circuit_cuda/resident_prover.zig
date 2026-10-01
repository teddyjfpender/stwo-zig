//! Complete proof-owned CUDA execution of the circuit recursion STARK.
//! Host work before ingress derives fixed geometry, literal tables, and the
//! circuit's public preprocessed identity. After ingress, only the resident
//! stage schedule runs until the single terminal proof publication.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const cuda = @import("stwo_cuda_backend");
const air_aot = @import("air_aot.zig");
const geometry_module = @import("geometry.zig");
const witness = @import("resident_witness.zig");
const interaction = @import("resident_interaction.zig");
const composition = @import("resident_composition.zig");
const composition_controller = @import("resident_composition_controller.zig");
const commit = @import("resident_commit.zig");
const oods = @import("resident_oods.zig");
const quotient = @import("resident_quotient.zig");
const fri = @import("resident_fri.zig");
const decommit = @import("resident_decommit.zig");
const terminal = @import("resident_terminal_bundle.zig");
const terminal_decode = @import("resident_terminal_decode.zig");
const proof_layout = @import("resident_proof_layout.zig");
const transcript = @import("resident_transcript.zig");
const memory = @import("resident_memory_plan.zig");
const binding = @import("resident_memory_binding.zig");
const pipeline = @import("resident_pipeline.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Plain = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

pub const Profile = enum { internal, root };

pub const Input = struct {
    values: []const QM31,
    preprocessed: *const circuit.common.preprocessed.PreprocessedCircuit,
    air: *const cpu.air.Bundle,
    catalog: *const air_aot.Catalog,
    config: core.pcs.config_v2.PcsConfigV2,
    profile: Profile,
    expected_preprocessed_root: ?[8]u32 = null,
    /// A process-owned runtime for consecutive recursive proofs. Standalone
    /// callers leave this null and get the original proof-owned session.
    runtime: ?*cuda.runtime.NativeRuntime = null,
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    terminal_proof: terminal_decode.Proof,
    stark: core.proof.StarkProof(Plain),
    verdict: cuda.runtime.verdict.Verdict,
    geometry_identity: [32]u8,
    planned_arena_bytes: usize,

    pub fn deinit(self: *Result) void {
        self.stark.deinit(self.allocator);
        self.terminal_proof.deinit(self.allocator);
        self.* = undefined;
    }
};

/// This API returns decoded material and a strict residency receipt. A
/// consumer must independently verify the STARK before publishing it as a
/// recursive child proof; decoding alone is not verification.
pub fn prove(allocator: std.mem.Allocator, input: Input) !Result {
    var phase = try std.time.Timer.start();
    if (input.values.len == 0 or input.preprocessed.n_outputs == 0 or
        input.preprocessed.n_outputs + circuit.witness.trace.U_VAR_IDX + 1 > input.values.len)
        return error.InvalidCircuitResidentInput;
    const layout = input.preprocessed.layout();
    var geometry = try geometry_module.Geometry.init(allocator, &layout, input.air, input.catalog, input.config);
    defer geometry.deinit();
    const blowup = input.config.fri_config.log_blowup_factor;
    const first_permutation_row = input.preprocessed.first_permutation_row;
    const witness_plan = try witness.Plan.init(&layout, first_permutation_row);
    const interaction_plan = try interaction.Plan.init(&layout);
    var composition_plan = try composition.Plan.init(allocator, &layout, input.air, input.catalog);
    defer composition_plan.deinit();
    var commit_plans: [4]commit.Plan = undefined;
    var commit_count: usize = 0;
    defer for (commit_plans[0..commit_count]) |*plan| plan.deinit();
    for (geometry.trees, &commit_plans) |tree, *plan| {
        plan.* = try commit.Plan.init(allocator, tree, blowup);
        commit_count += 1;
    }
    var oods_plan = try oods.Plan.init(allocator, input.air, &geometry, blowup);
    defer oods_plan.deinit();
    var quotient_topology = try quotient.derive(allocator, input.air, &geometry, &oods_plan, blowup);
    defer quotient_topology.deinit();
    const twiddle_words = try pow2(geometry.fri_input_log - 1);
    var fri_plan = try fri.Plan.init(allocator, &geometry, input.config, twiddle_words);
    defer fri_plan.deinit();
    var decommit_plan = try decommit.Plan.init(allocator, &geometry, input.config);
    defer decommit_plan.deinit();
    const terminal_layout = try terminal.Layout.init(&geometry, &oods_plan, input.config);
    const terminal_decommit = terminal.Decommit{ .capacity_words = decommit_plan.topology.assembly_capacity_words };
    var terminal_bundle = try terminal.Bundle.init(allocator, terminal_layout, terminal_decommit);
    defer terminal_bundle.deinit(allocator);
    var logical = try proof_layout.Layout.init(allocator, &geometry, &oods_plan, input.config);
    defer logical.deinit(allocator);
    var memory_plan = try memory.Plan.init(allocator, .{
        .value_count = input.values.len,
        .twiddle_words = twiddle_words,
        .commitments = &commit_plans,
        .interaction = &interaction_plan,
        .composition = &composition_plan,
        .oods = &oods_plan,
        .quotient = &quotient_topology,
        .fri = &fri_plan,
        .decommit = &decommit_plan,
        .terminal = &terminal_bundle,
    });
    defer memory_plan.deinit();
    const planned_arena_bytes = try memory_plan.bytes();
    var twiddles = try Twiddles.init(allocator, twiddle_words);
    defer twiddles.deinit();
    const plan_ns = phase.lap();

    // The preprocessed root is circuit-static and may be cached across
    // proofs of the same topology. The GPU still commits that tree and the
    // native verifier checks the committed root against this identity.
    const pp_root = if (input.expected_preprocessed_root) |words|
        core.vcs.blake2_hash.digestFromU32s(words)
    else
        try input.preprocessed.preprocessedRoot(allocator, blowup);
    const sizes = try circuit.common.component_list.circuitComponentLogSizes(&layout);
    const circuit_hash = try circuit.common.circuit_hash.hostCircuitHash(sizes, blowup, pp_root);
    const hash_words = core.vcs.blake2_hash.digestToU32s(circuit_hash);
    const static_hash_ns = phase.lap();

    var placement = try memory_plan.placement.clone(allocator);
    var tx = if (input.runtime) |runtime| blk: {
        const retained = runtime.beginProof() catch |err| {
            placement.deinit(allocator);
            return err;
        };
        break :blk try cuda.runtime.proof_transaction.ResidentProofTransaction.openPreparedRetained(
            allocator,
            retained,
            placement,
        );
    } else try cuda.runtime.proof_transaction.ResidentProofTransaction.openPrepared(
        allocator,
        &.{ 80, 90 },
        placement,
    );
    var finished = false;
    defer if (!finished) tx.abort() catch {};
    const session = tx.proofSession();
    var views = try binding.bind(allocator, &tx, .{
        .plans = &memory_plan,
        .commitments = &commit_plans,
        .interaction = &interaction_plan,
        .fri = &fri_plan,
        .terminal = &terminal_bundle,
        .output_count = input.preprocessed.n_outputs,
    });
    defer views.deinit();
    try ingress(&tx, &memory_plan, input, &views, &terminal_bundle, &twiddles, &hash_words);

    var sink = try transcript.NativeSink.init(session, views.transcript, @enumFromInt(@intFromEnum(input.profile)), geometry.identity);
    try sink.prime(0, input.config);
    var commits: [4]commit.Bound = undefined;
    for (&commits, &commit_plans, &views.commits) |*bound, *plan, buffers| {
        bound.* = try commit.Bound.init(plan, buffers);
        try bound.prime(session);
    }
    var relation = try interaction.Bound.init(&interaction_plan, views.interaction);
    try relation.prime(session);
    var evaluator = try composition_controller.Bound.init(allocator, &composition_plan, views.composition);
    defer evaluator.deinit();
    try evaluator.prime(session);
    try oods_plan.upload(session, views.oods);
    var oods_bound = try oods_plan.bind(allocator, views.commits);
    defer oods_bound.deinit();
    var quotient_bound = try quotient.prepareResident(
        allocator,
        session,
        input.air,
        &geometry,
        &oods_plan,
        blowup,
        views.commits,
        views.oods,
        views.quotient,
        views.twiddles_forward,
        views.twiddles_inverse,
    );
    defer quotient_bound.deinit();
    try fri_plan.upload(session, views.fri, views.twiddles_inverse);
    try decommit_plan.upload(session, views.decommit);
    try tx.finishIngress();
    const ingress_ns = phase.lap();

    var schedule = pipeline.Bound{
        .transaction = &tx,
        .sink = &sink,
        .witness = &witness_plan,
        .interaction = &relation,
        .composition = &evaluator,
        .oods = &oods_bound,
        .quotient = &quotient_bound,
        .fri_plan = &fri_plan,
        .decommit_plan = &decommit_plan,
        .commitments = &commits,
        .preprocessed_columns = views.preprocessed,
        .base_columns = views.base,
        .interaction_columns = views.interaction_columns,
        .values = views.values,
        .output_values = views.output_values,
        .circuit_hash = views.circuit_hash,
        .error_flag = views.error_flag,
        .oods_view = views.oods,
        .quotient_challenge = views.quotient.challenge,
        .fri_view = views.fri,
        .decommit_view = views.decommit,
        .decommit_assembly = views.proof.decommitment,
        .proof = views.proof,
        .twiddles_inverse = views.twiddles_inverse,
    };
    try schedule.execute(allocator, input.config);
    const schedule_ns = phase.lap();
    const transport = try allocator.alloc(u32, terminal_bundle.total_words);
    defer allocator.free(transport);
    const proof_slot = (try memory_plan.slot(.terminal_bundle, 0)).requirement.id;
    const verdict = try tx.assembleAndFinish(transport, proof_slot);
    const finish_ns = phase.lap();
    finished = true;
    if (!verdict.isResident()) return error.NonresidentCircuitProof;
    var decoded = terminal_decode.Proof.decode(
        allocator,
        terminal_layout,
        terminal_decommit,
        transport,
        .{
            .operations = verdict.counters.d2h_proof_operations,
            .bytes = verdict.counters.d2h_proof_bytes,
            .runtime_compile_attempts = verdict.aot.aot_misses,
            .cpu_fallback_attempts = verdict.counters.cpu_fallback_attempts,
        },
    ) catch |err| {
        const section = terminal_bundle.section(.decommitment);
        const head = transport[section.offset_words..][0..@min(section.words, 8)];
        std.log.err("resident circuit terminal decode: {s}; decommitment head={any}; proof reads={} bytes={}", .{
            @errorName(err), head, verdict.counters.d2h_proof_operations, verdict.counters.d2h_proof_bytes,
        });
        if (section.words >= 8 + 16 * 9) {
            const words = transport[section.offset_words..][0..section.words];
            for (0..9) |index| {
                const meta = words[8 + index * 16 ..][0..16];
                std.log.err("resident circuit opening tree={} kind={} role={} queries={} values={} hashes={} aux={} all_values={} used={}", .{
                    index, meta[0], meta[1], meta[3], meta[5], meta[9], meta[11], meta[13], meta[15],
                });
            }
        }
        return err;
    };
    errdefer decoded.deinit(allocator);
    const stark = try decoded.decodeStarkProof(allocator, &logical, input.config);
    std.debug.print("circuit-cuda resident-phase profile={s} plan_ns={} static_hash_ns={} ingress_ns={} schedule_ns={} finish_ns={} decode_ns={}\n", .{
        @tagName(input.profile), plan_ns, static_hash_ns, ingress_ns, schedule_ns, finish_ns, phase.lap(),
    });
    return .{
        .allocator = allocator,
        .terminal_proof = decoded,
        .stark = stark,
        .verdict = verdict,
        .geometry_identity = geometry.identity,
        .planned_arena_bytes = planned_arena_bytes,
    };
}

fn ingress(
    tx: *cuda.runtime.proof_transaction.ResidentProofTransaction,
    plan: *const memory.Plan,
    input: Input,
    views: *const binding.Views,
    bundle: *const terminal.Bundle,
    twiddles: *const Twiddles,
    hash_words: *const [8]u32,
) !void {
    const session = tx.proofSession();
    const value_words: [*]const u32 = @ptrCast(input.values.ptr);
    try session.context.uploadSlice(u32, views.values, value_words[0 .. input.values.len * 4]);
    for (input.preprocessed.columns, views.preprocessed) |column, destination| {
        if (destination.len != column.values.len) return error.InvalidCircuitResidentInput;
        const source: [*]const u32 = @ptrCast(column.values.ptr);
        try session.context.uploadSlice(u32, destination, source[0..column.values.len]);
    }
    try session.context.uploadSlice(u32, views.twiddles_forward, twiddles.forwardWords());
    try session.context.uploadSlice(u32, views.twiddles_inverse, twiddles.inverseWords());
    try session.context.uploadSlice(u32, views.circuit_hash, hash_words);
    const terminal_id = (try plan.slot(.terminal_bundle, 0)).requirement.id;
    try tx.zeroResidentSlice(u32, .ingress, terminal_id, 0, bundle.total_words);
    try session.context.uploadSlice(u32, try views.proof.bundle.sub(0, bundle.static_header.len), bundle.static_header);
}

const Twiddles = struct {
    allocator: std.mem.Allocator,
    tree: prover.poly.twiddles.TwiddleTree([]M31),

    fn init(allocator: std.mem.Allocator, words: usize) !Twiddles {
        if (words == 0 or !std.math.isPowerOfTwo(words)) return error.InvalidCircuitTwiddles;
        const circle_log: u32 = @intCast(std.math.log2_int(usize, words) + 1);
        const coset = core.poly.circle.CanonicCoset.new(circle_log).circleDomain().half_coset;
        var tree = try prover.poly.twiddles.precomputeM31Parallel(allocator, coset);
        errdefer prover.poly.twiddles.deinitM31(allocator, &tree);
        if (tree.twiddles.len != words or tree.itwiddles.len != words) return error.InvalidCircuitTwiddles;
        return .{ .allocator = allocator, .tree = tree };
    }
    fn deinit(self: *Twiddles) void {
        prover.poly.twiddles.deinitM31(self.allocator, &self.tree);
    }
    fn forwardWords(self: *const Twiddles) []const u32 {
        const ptr: [*]const u32 = @ptrCast(self.tree.twiddles.ptr);
        return ptr[0..self.tree.twiddles.len];
    }
    fn inverseWords(self: *const Twiddles) []const u32 {
        const ptr: [*]const u32 = @ptrCast(self.tree.itwiddles.ptr);
        return ptr[0..self.tree.itwiddles.len];
    }
};

fn pow2(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.CircuitResidentSizeOverflow;
    return @as(usize, 1) << @intCast(log);
}

test "full circuit recursion CUDA prover typechecks the resident transaction" {
    const entry: *const fn (std.mem.Allocator, Input) anyerror!Result = &prove;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
