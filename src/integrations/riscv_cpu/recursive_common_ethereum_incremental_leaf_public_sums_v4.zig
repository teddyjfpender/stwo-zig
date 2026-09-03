//! Fixed schema-3 arithmetic authority for the role-0 V4 public sums.
//!
//! One value-independent graph is derived from the campaign's checked tuple
//! capacity. Per-leaf evaluations consume the exact 412-word SpanStatement,
//! fixed register-clock limbs from the authenticated V2 wire, the complete
//! committed role-aware tuple stream, and the verifier-drawn native relation
//! challenges. Sparse-RW and continuation-tree terms are absent by design;
//! role-aware I/O and the actual Ethereum-profile completion fetch replace
//! them exactly once.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const arithmetic = frontend.recursion.arithmetic_circuit;
const graph_mod = frontend.recursion.air.composition_circuit;
const lowering = frontend.recursion.air.verifier_arithmetic_lowering;
const native_sum = frontend.recursion.segment_public_native_sum_authority_v2;
const segment_v2 = frontend.recursion.segment_statement_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const CIRCUIT_ID: u32 = native_sum.CIRCUIT_ID;
pub const PRODUCTION_LEAF_COUNT = campaign_mod.PRODUCTION_LEAF_COUNT;
pub const FIXED_VALUE_INDEPENDENT_PROGRAM = true;
pub const SPARSE_RW_TERMS_INCLUDED = false;
pub const CONTINUATION_COMPENSATION_INCLUDED = false;
pub const ROLE_AWARE_IO_TERMS_INCLUDED = true;
pub const ACTUAL_COMPLETION_PROGRAM_TERM_INCLUDED = true;
pub const PRODUCTION_ACTIVATION = false;

const PROGRAM_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-sums-program/v4-schema3\x00";
const EVALUATION_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-sums-evaluation/v4-schema3\x00";

pub const InputSourceV4 = support.InputSourceV4;
pub const Boundary = support.Boundary;
pub const Selector = support.Selector;
pub const Domain = support.Domain;
pub const RegisterClockCoordinateV4 = support.RegisterClockCoordinateV4;
pub const RegisterByteCoordinateV4 = support.RegisterByteCoordinateV4;
pub const TupleSelectorCoordinateV4 = support.TupleSelectorCoordinateV4;

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalPublicSumEvaluationMismatchV4,
    EthereumIncrementalPublicSumProgramMismatchV4,
    InvalidFieldElement,
};

pub fn FixedProgramV4ForCount(comptime campaign_leaf_count: usize) type {
    const Campaign = campaign_mod.CampaignProviderGeometryAuthorityV4ForCount(
        campaign_leaf_count,
    );
    return FixedProgramV4ForAuthority(Campaign);
}

pub const OwnedFixedProgramV4 = FixedProgramV4ForAuthority(
    campaign_mod.OwnedCampaignProviderGeometryV4,
);

fn FixedProgramV4ForAuthority(comptime Campaign: type) type {
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        tuple_capacity: u32,
        campaign_geometry_identity_sha256: [32]u8,
        circuit: arithmetic.Circuit,
        bindings: []InputSourceV4,
        graph_nodes: []graph_mod.Node,
        graph_outputs: []u32,
        graph: graph_mod.CircuitGraph,
        program_identity_sha256: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            campaign: *const Campaign,
        ) !Self {
            try campaign.validateStructure();
            const capacity =
                campaign.provider_geometry.role_io_tuple_capacity;
            var built = try support.build(allocator, capacity);
            var built_owned = true;
            defer if (built_owned) built.deinit(allocator);
            const graph_nodes = try allocator.alloc(
                graph_mod.Node,
                built.circuit.nodes().len,
            );
            errdefer allocator.free(graph_nodes);
            for (graph_nodes, built.circuit.nodes()) |*destination, source|
                destination.* = support.graphNode(source);
            const graph_outputs = try allocator.dupe(
                u32,
                built.circuit.outputs(),
            );
            errdefer allocator.free(graph_outputs);
            const graph_identity = graph_mod.computeGraphDigest(
                graph_nodes,
                graph_outputs,
            );
            const graph = try graph_mod.CircuitGraph.authenticate(
                graph_nodes,
                graph_outputs,
                graph_identity,
            );
            var result = Self{
                .allocator = allocator,
                .tuple_capacity = capacity,
                .campaign_geometry_identity_sha256 = campaign.geometry_identity_sha256,
                .circuit = built.circuit,
                .bindings = built.bindings,
                .graph_nodes = graph_nodes,
                .graph_outputs = graph_outputs,
                .graph = graph,
                .program_identity_sha256 = undefined,
            };
            built_owned = false;
            result.program_identity_sha256 = programIdentity(&result);
            try result.validateAgainstCampaign(campaign);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.graph_outputs);
            self.allocator.free(self.graph_nodes);
            self.allocator.free(self.bindings);
            self.circuit.deinit();
            self.* = undefined;
        }

        pub fn validateAgainstCampaign(
            self: *const Self,
            campaign: *const Campaign,
        ) !void {
            try campaign.validateStructure();
            try self.circuit.validate();
            try self.graph.validate();
            const expected_graph_identity = graph_mod.computeGraphDigest(
                self.graph_nodes,
                self.graph_outputs,
            );
            const expected_program_identity = programIdentity(self);
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.tuple_capacity !=
                    campaign.provider_geometry.role_io_tuple_capacity or
                self.bindings.len != try support.inputCount(
                    self.tuple_capacity,
                ) or
                self.circuit.inputNodes().len != self.bindings.len or
                self.graph_nodes.len != self.circuit.nodes().len or
                self.graph_outputs.len != self.circuit.outputs().len or
                self.graph.nodes.ptr != self.graph_nodes.ptr or
                self.graph.outputs.ptr != self.graph_outputs.ptr or
                !std.mem.eql(
                    u8,
                    &self.campaign_geometry_identity_sha256,
                    &campaign.geometry_identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.graph.identity_digest,
                    &expected_graph_identity,
                ) or
                !std.mem.eql(
                    u8,
                    &self.program_identity_sha256,
                    &expected_program_identity,
                ))
            {
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            }
            for (
                self.graph_nodes,
                self.circuit.nodes(),
            ) |graph_node, circuit_node| if (!std.meta.eql(
                graph_node,
                support.graphNode(circuit_node),
            )) return error.EthereumIncrementalPublicSumProgramMismatchV4;
            if (!std.mem.eql(u32, self.graph_outputs, self.circuit.outputs()))
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            for (self.circuit.inputNodes(), 0..) |node, index| {
                const expected = std.math.cast(u32, index) orelse
                    return error.EthereumIncrementalPublicSumProgramMismatchV4;
                if (node != expected)
                    return error.EthereumIncrementalPublicSumProgramMismatchV4;
            }
        }

        pub fn loweringLane(self: *const Self) lowering.Lane {
            return .{
                .circuit_id = CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = self.program_identity_sha256,
                .graph = self.graph,
            };
        }
    };
}

pub const FixedProgramV4 = FixedProgramV4ForCount(PRODUCTION_LEAF_COUNT);

pub fn OwnedEvaluationV4ForCount(
    comptime Engine: type,
    comptime campaign_leaf_count: usize,
) type {
    const Program = FixedProgramV4ForCount(campaign_leaf_count);
    const Materialized = campaign_materializer.PreparedCampaignCaptureV4ForCount(
        Engine,
        campaign_leaf_count,
    );
    return OwnedEvaluationV4ForTypes(Engine, Program, Materialized);
}

pub fn OwnedRuntimeEvaluationV4(comptime Engine: type) type {
    return OwnedEvaluationV4ForTypes(
        Engine,
        OwnedFixedProgramV4,
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine),
    );
}

fn OwnedEvaluationV4ForTypes(
    comptime Engine: type,
    comptime Program: type,
    comptime Materialized: type,
) type {
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        program_identity_sha256: [32]u8,
        materialized_identity_sha256: [32]u8,
        campaign_authority_identity_sha256: [32]u8,
        evaluation: arithmetic.Evaluation,
        evaluation_identity_sha256: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            program: *const Program,
            materialized: *const Materialized,
        ) !Self {
            try materialized.validate();
            try program.validateAgainstCampaign(
                materialized.campaign_authority,
            );
            const inputs = try allocator.alloc(QM31, program.bindings.len);
            defer allocator.free(inputs);
            try fillInputs(Engine, materialized, program.bindings, inputs);
            var evaluation = try program.circuit.evaluate(allocator, inputs);
            errdefer evaluation.deinit();
            if (!try program.circuit.outputsAreZero(evaluation.values))
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            var result = Self{
                .allocator = allocator,
                .program_identity_sha256 = program.program_identity_sha256,
                .materialized_identity_sha256 = materialized.identity_sha256,
                .campaign_authority_identity_sha256 = materialized.campaign_authority.authority_identity_sha256,
                .evaluation = evaluation,
                .evaluation_identity_sha256 = undefined,
            };
            result.evaluation_identity_sha256 = evaluationIdentity(&result);
            try result.validateAgainst(program, materialized);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.evaluation.deinit();
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const Self,
            program: *const Program,
            materialized: *const Materialized,
        ) !void {
            try materialized.validate();
            try program.validateAgainstCampaign(
                materialized.campaign_authority,
            );
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.evaluation.values.len != program.circuit.nodes().len or
                !std.mem.eql(
                    u8,
                    &self.program_identity_sha256,
                    &program.program_identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.materialized_identity_sha256,
                    &materialized.identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.campaign_authority_identity_sha256,
                    &materialized.campaign_authority.authority_identity_sha256,
                ) or
                !try program.circuit.outputsAreZero(self.evaluation.values) or
                !std.mem.eql(
                    u8,
                    &self.evaluation_identity_sha256,
                    &evaluationIdentity(self),
                ))
            {
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            }
            const inputs = try self.allocator.alloc(
                QM31,
                program.bindings.len,
            );
            defer self.allocator.free(inputs);
            try fillInputs(Engine, materialized, program.bindings, inputs);
            var expected = try program.circuit.evaluate(
                self.allocator,
                inputs,
            );
            defer expected.deinit();
            if (!std.mem.eql(
                u8,
                std.mem.sliceAsBytes(self.evaluation.values),
                std.mem.sliceAsBytes(expected.values),
            )) return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
        }

        pub fn loweringEvaluation(
            self: *const Self,
            program: *const Program,
        ) !lowering.Evaluation {
            if (!std.mem.eql(
                u8,
                &self.program_identity_sha256,
                &program.program_identity_sha256,
            ) or self.evaluation.values.len != program.graph.nodes.len)
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            return .{
                .circuit_identity = self.program_identity_sha256,
                .values = self.evaluation.values,
            };
        }
    };
}

pub fn OwnedEvaluationV4(comptime Engine: type) type {
    return OwnedEvaluationV4ForCount(Engine, PRODUCTION_LEAF_COUNT);
}

fn fillInputs(
    comptime Engine: type,
    materialized: anytype,
    bindings: []const InputSourceV4,
    destination: []QM31,
) !void {
    if (destination.len != bindings.len)
        return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
    const capture = &materialized.base.input.stage101;
    const native_words = capture.public_data.data.words();
    const role = &capture.role_aware_public.value;
    const published = materialized.role_aware_io.public_sum_row.values();
    for (bindings, destination) |binding, *output| output.* = switch (binding) {
        .segment_selector => QM31.one(),
        .statement_word => |index| QM31.fromBase(M31.fromCanonical(
            materialized.base.input.statement_words[index],
        )),
        .register_clock_limb => |coordinate| QM31.fromBase(native_words[
            registerClockIndex(coordinate)
        ]),
        .register_byte => |coordinate| QM31.fromBase(M31.fromCanonical(
            registerByte(role, coordinate),
        )),
        .role_io_word => |index| QM31.fromBase(M31.fromCanonical(
            materialized.role_aware_io.canonical_words[index],
        )),
        .tuple_selector => |coordinate| QM31.fromBase(M31.fromCanonical(
            tupleSelector(&materialized.role_aware_io, coordinate),
        )),
        .published_value_word => |coordinate| QM31.fromBase(
            published[coordinate.value].toM31Array()[coordinate.limb],
        ),
        .relation_challenge_word => |coordinate| blk: {
            const value = switch (coordinate.domain) {
                .registers_state => if (coordinate.alpha)
                    capture.relations.base.registers_state.alpha
                else
                    capture.relations.base.registers_state.z,
                .memory_access => if (coordinate.alpha)
                    capture.relations.base.memory_access.alpha
                else
                    capture.relations.base.memory_access.z,
                .program_access => if (coordinate.alpha)
                    capture.relations.base.program_access.alpha
                else
                    capture.relations.base.program_access.z,
                .merkle => if (coordinate.alpha)
                    capture.relations.base.merkle.alpha
                else
                    capture.relations.base.merkle.z,
            };
            break :blk QM31.fromBase(value.toM31Array()[coordinate.limb]);
        },
    };
    _ = Engine;
}

fn registerClockIndex(
    coordinate: RegisterClockCoordinateV4,
) usize {
    const start = if (coordinate.boundary == .entry)
        segment_v2.fixed_layout.entry_register_clocks
    else
        segment_v2.fixed_layout.exit_register_clocks;
    return start + @as(usize, coordinate.register) * 2 + coordinate.limb;
}

fn registerByte(
    public: anytype,
    coordinate: RegisterByteCoordinateV4,
) u32 {
    const value = if (coordinate.boundary == .entry)
        public.initial_regs[coordinate.register]
    else
        public.final_regs[coordinate.register];
    const byte_index: u32 = coordinate.byte;
    const shift: u5 = @intCast(8 * byte_index);
    return @as(u8, @truncate(value >> shift));
}

fn tupleSelector(
    witness: *const role_io.OwnedWitnessV4,
    coordinate: TupleSelectorCoordinateV4,
) u32 {
    const tuple = witness.tuples[coordinate.slot];
    const actual: Selector = if (tuple.isZero())
        .padding
    else
        @enumFromInt(@intFromEnum(tuple.kind));
    return @intFromBool(actual == coordinate.selector);
}

fn programIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, CIRCUIT_ID);
    hashInt(&hash, u32, value.tuple_capacity);
    hash.update(&value.campaign_geometry_identity_sha256);
    hash.update(&value.graph.identity_digest);
    hashInt(&hash, u64, value.bindings.len);
    for (value.bindings) |binding| hashBinding(&hash, binding);
    for (value.circuit.useCounts()) |count| hashInt(&hash, u32, count);
    return hash.finalResult();
}

fn evaluationIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(EVALUATION_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.materialized_identity_sha256);
    hash.update(&value.campaign_authority_identity_sha256);
    hashInt(&hash, u64, value.evaluation.values.len);
    for (value.evaluation.values) |field| for (field.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashBinding(hash: anytype, value: InputSourceV4) void {
    hashInt(hash, u8, @intFromEnum(value));
    switch (value) {
        .segment_selector => {},
        .statement_word => |index| hashInt(hash, u16, index),
        .register_clock_limb => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.boundary));
            hashInt(hash, u8, coordinate.register);
            hashInt(hash, u8, coordinate.limb);
        },
        .register_byte => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.boundary));
            hashInt(hash, u8, coordinate.register);
            hashInt(hash, u8, coordinate.byte);
        },
        .role_io_word => |index| hashInt(hash, u32, index),
        .tuple_selector => |coordinate| {
            hashInt(hash, u32, coordinate.slot);
            hashInt(hash, u8, @intFromEnum(coordinate.selector));
        },
        .published_value_word => |coordinate| {
            hashInt(hash, u8, coordinate.value);
            hashInt(hash, u8, coordinate.limb);
        },
        .relation_challenge_word => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.domain));
            hashInt(hash, u8, @intFromBool(coordinate.alpha));
            hashInt(hash, u8, coordinate.limb);
        },
    }
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        PRODUCTION_LEAF_COUNT != 210 or
        !FIXED_VALUE_INDEPENDENT_PROGRAM or SPARSE_RW_TERMS_INCLUDED or
        CONTINUATION_COMPENSATION_INCLUDED or
        !ROLE_AWARE_IO_TERMS_INCLUDED or
        !ACTUAL_COMPLETION_PROGRAM_TERM_INCLUDED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public-sum V4 drifted");
    }
}
