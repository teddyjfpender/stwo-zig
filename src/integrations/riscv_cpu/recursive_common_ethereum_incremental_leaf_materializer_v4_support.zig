//! Process-local construction custody and timing for the role-0 materializer.
//! Neither type is serializable proof authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const public_semantics =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const QM31 = stwo_core.fields.qm31.QM31;
const bridge = frontend.air.memory_commitment.incremental_bridge_v2;
const TOKEN_DOMAIN =
    "stwo-zig/common-ethereum-incremental-materializer-construction/v4\x00";
const MATERIALIZER_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-materializer/v4\x00";

pub const SERIALIZABLE_CONSTRUCTION_CUSTODY = false;
pub const MAX_MATERIALIZATION_WORKERS: usize = 256;
pub const BRIDGE_DETAILED_CLAIM_COUNT: u32 = 1;
pub const BRIDGE_TRANSCRIPT_CLAIM_COUNT: u32 = 1;
pub const BRIDGE_TRACE_SAMPLED_VALUE_COUNT: u32 =
    2 + bridge.N_MAIN_COLUMNS + 2 * bridge.N_INTERACTION_COLUMNS;

pub const ExecutionV4 = struct {
    worker_count: usize = 1,

    pub fn validate(self: ExecutionV4) !void {
        if (self.worker_count == 0 or
            self.worker_count > MAX_MATERIALIZATION_WORKERS)
        {
            return error.InvalidMaterializationWorkerCountV4;
        }
    }
};

pub const MetricsV4 = struct {
    input_validation_ns: u64 = 0,
    public_witness_ns: u64 = 0,
    transcript_ns: u64 = 0,
    base_profile_ns: u64 = 0,
    program_compile_ns: u64 = 0,
    composition_prepare_ns: u64 = 0,
    fri_capture_ns: u64 = 0,
    final_seal_ns: u64 = 0,
    total_ns: u64 = 0,

    graph_node_count: u64 = 0,
    graph_node_bytes: u64 = 0,
    graph_output_bytes: u64 = 0,
    graph_binding_bytes: u64 = 0,
    retained_schedule_bytes: u64 = 0,
    evaluation_bytes: u64 = 0,
    input_value_bytes: u64 = 0,
    detailed_claim_bytes: u64 = 0,

    graph_schedule_compile_count: u8 = 0,
    retained_graph_copy_count: u8 = 0,
    schedule_projection_worker_count: u16 = 1,
};

/// Pointer-free bridge geometry projected from the same stage-101 profile
/// accepted by the cold verifier.
pub const BridgeProjectionV4 = struct {
    format_version: u16 = 4,
    schema_version: u16 = 3,
    log_size: u32,
    n_rows: u32,
    trace_sampled_value_count: u32 = BRIDGE_TRACE_SAMPLED_VALUE_COUNT,
    detailed_claim_count: u32 = BRIDGE_DETAILED_CLAIM_COUNT,
    transcript_claim_count: u32 = BRIDGE_TRANSCRIPT_CLAIM_COUNT,
    direct_constraint_count: u32 = bridge.N_CONSTRAINTS,
    composition_log_split: u32 = 1,
    geometry_identity_sha256: [32]u8,

    pub fn init(profile: anytype) !BridgeProjectionV4 {
        const preprocessed = std.math.cast(
            u32,
            profile.bridge_geometry.placement.is_first_col_idx,
        ) orelse return error.ArithmeticOverflow;
        const main = std.math.cast(
            u32,
            profile.bridge_geometry.placement.main_col_offset,
        ) orelse return error.ArithmeticOverflow;
        const interaction = std.math.cast(
            u32,
            profile.bridge_geometry.placement.interaction_col_offset,
        ) orelse return error.ArithmeticOverflow;
        try profile.bridge_geometry.validateAfterPrefix(.{
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        });
        var result = BridgeProjectionV4{
            .log_size = profile.bridge_geometry.log_size,
            .n_rows = profile.bridge_geometry.n_rows,
            .geometry_identity_sha256 = profile.bridge_geometry.identity_sha256,
        };
        try result.validateAgainst(profile);
        return result;
    }

    pub fn validateAgainst(self: BridgeProjectionV4, profile: anytype) !void {
        if (self.format_version != 4 or self.schema_version != 3 or
            self.log_size < 4 or self.log_size >= 31 or self.n_rows == 0 or
            self.n_rows > (@as(u32, 1) << @intCast(self.log_size)) or
            self.trace_sampled_value_count !=
                BRIDGE_TRACE_SAMPLED_VALUE_COUNT or
            self.detailed_claim_count != BRIDGE_DETAILED_CLAIM_COUNT or
            self.transcript_claim_count != BRIDGE_TRANSCRIPT_CLAIM_COUNT or
            self.direct_constraint_count != bridge.N_CONSTRAINTS or
            self.composition_log_split != 1 or
            self.log_size != profile.bridge_geometry.log_size or
            self.n_rows != profile.bridge_geometry.n_rows or
            !std.mem.eql(
                u8,
                &self.geometry_identity_sha256,
                &profile.bridge_geometry.identity_sha256,
            ))
        {
            return error.EthereumIncrementalMaterializerMismatchV4;
        }
    }
};

/// Seals allocation identity plus compact authenticated program identities.
/// It is minted only immediately after `compileRetainingSchedule`; callers at
/// an independent boundary must use the program's O(graph) deep validation.
pub const ProgramConstructionCustodyV4 = struct {
    nodes_ptr: usize,
    nodes_len: usize,
    outputs_ptr: usize,
    outputs_len: usize,
    bindings_ptr: usize,
    bindings_len: usize,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    seal: [32]u8,

    pub fn mint(program: anytype) !ProgramConstructionCustodyV4 {
        if (program.nodes.len == 0 or program.outputs.len == 0 or
            program.bindings.len == 0)
        {
            return error.InvalidFreshProgramConstructionCustodyV4;
        }
        var result = ProgramConstructionCustodyV4{
            .nodes_ptr = @intFromPtr(program.nodes.ptr),
            .nodes_len = program.nodes.len,
            .outputs_ptr = @intFromPtr(program.outputs.ptr),
            .outputs_len = program.outputs.len,
            .bindings_ptr = @intFromPtr(program.bindings.ptr),
            .bindings_len = program.bindings.len,
            .graph_sha256 = program.graph_sha256,
            .reference_sha256 = program.reference_sha256,
            .schedule_sha256 = program.schedule_sha256,
            .air_program_identity = program.air_program_identity,
            .verifier_program_authority = program.verifier_program_authority,
            .seal = undefined,
        };
        result.seal = seal(&result);
        return result;
    }

    pub fn validateBorrowed(
        self: ProgramConstructionCustodyV4,
        program: anytype,
    ) !void {
        if (self.nodes_ptr != @intFromPtr(program.nodes.ptr) or
            self.nodes_len != program.nodes.len or
            self.outputs_ptr != @intFromPtr(program.outputs.ptr) or
            self.outputs_len != program.outputs.len or
            self.bindings_ptr != @intFromPtr(program.bindings.ptr) or
            self.bindings_len != program.bindings.len or
            !std.meta.eql(self.graph_sha256, program.graph_sha256) or
            !std.meta.eql(self.reference_sha256, program.reference_sha256) or
            !std.meta.eql(self.schedule_sha256, program.schedule_sha256) or
            !std.meta.eql(
                self.air_program_identity,
                program.air_program_identity,
            ) or !std.meta.eql(
            self.verifier_program_authority,
            program.verifier_program_authority,
        ) or !std.meta.eql(self.seal, seal(&self))) {
            return error.InvalidFreshProgramConstructionCustodyV4;
        }
    }
};

pub fn recordProgramResources(
    metrics: *MetricsV4,
    program: anytype,
    schedule: anytype,
) !void {
    metrics.graph_schedule_compile_count = std.math.add(
        u8,
        metrics.graph_schedule_compile_count,
        1,
    ) catch return error.ArithmeticOverflow;
    // Program owns the only graph arrays; Prepared borrows them exactly.
    metrics.retained_graph_copy_count = 0;
    metrics.graph_node_count = @intCast(program.nodes.len);
    metrics.graph_node_bytes = try allocationBytes(
        program.nodes.len,
        std.meta.Child(@TypeOf(program.nodes)),
    );
    metrics.graph_output_bytes = try allocationBytes(
        program.outputs.len,
        std.meta.Child(@TypeOf(program.outputs)),
    );
    metrics.graph_binding_bytes = try allocationBytes(
        program.bindings.len,
        std.meta.Child(@TypeOf(program.bindings)),
    );
    metrics.retained_schedule_bytes = try allocationBytes(
        schedule.rows.len,
        std.meta.Child(@TypeOf(schedule.rows)),
    );
    metrics.evaluation_bytes = try allocationBytes(program.nodes.len, QM31);
}

pub fn materializerIdentity(
    comptime Engine: type,
    value: anytype,
) [32]u8 {
    _ = Engine;
    var hash = Sha256.init(.{});
    hash.update(MATERIALIZER_IDENTITY_DOMAIN);
    hashInt(&hash, u16, 4);
    hashInt(&hash, u16, 3);
    hashInt(&hash, u8, @intFromEnum(manifest_mod.ROLE));
    hash.update(&value.input.capability_identity_sha256);
    hash.update(&value.role_aware_io.identity_sha256);
    hash.update(&value.schedule.identity_sha256);
    hashInt(&hash, u32, value.role_aware_io.active_tuple_count);
    hashInt(&hash, u32, value.role_aware_io.padded_tuple_capacity);
    hashInt(&hash, u32, value.schedule.provider_log_size);
    hashInt(&hash, u64, value.schedule.calls.len);
    hashInt(&hash, u32, value.provider_geometry.role_io_tuple_capacity);
    hashInt(&hash, u32, value.provider_geometry.provider_active_row_count);
    hashInt(&hash, u32, value.provider_geometry.provider_row_capacity);
    hash.update(&value.transcript.identity_sha256);
    hash.update(&value.completion_program_claim.identity_sha256);
    hash.update(&public_semantics.programIdentity());
    hash.update(&value.base_profile.identity_digest);
    hash.update(&value.composition_program.air_program_identity);
    hash.update(&value.composition_program.verifier_program_authority);
    hash.update(&value.composition_prepared.circuit.identity_digest);
    hash.update(&value.bridge.geometry_identity_sha256);
    hash.update(&value.captured_fri.circuit.identity_digest);
    hash.update(&value.captured_fri.pcs_circuit.identity_digest);
    for (value.schedule.source.source_digest) |word|
        hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.base_sampled_value_count);
    hashInt(&hash, u32, value.ethereum_sampled_value_count);
    hashInt(&hash, u32, value.full_sampled_value_count);
    hashInt(&hash, u32, value.full_detailed_claim_count);
    hashInt(&hash, u32, 43);
    return hash.finalResult();
}

fn seal(value: *const ProgramConstructionCustodyV4) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TOKEN_DOMAIN);
    hashInt(&hash, u16, 4);
    hashInt(&hash, usize, value.nodes_ptr);
    hashInt(&hash, usize, value.nodes_len);
    hashInt(&hash, usize, value.outputs_ptr);
    hashInt(&hash, usize, value.outputs_len);
    hashInt(&hash, usize, value.bindings_ptr);
    hashInt(&hash, usize, value.bindings_len);
    hash.update(&value.graph_sha256);
    hash.update(&value.reference_sha256);
    hash.update(&value.schedule_sha256);
    hash.update(&value.air_program_identity);
    hash.update(&value.verifier_program_authority);
    return hash.finalResult();
}

fn allocationBytes(count: usize, comptime T: type) !u64 {
    return std.math.mul(u64, @intCast(count), @sizeOf(T)) catch
        return error.ArithmeticOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
