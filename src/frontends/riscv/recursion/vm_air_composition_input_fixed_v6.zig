//! Candidate verifier-built row-18 fixed columns. The graph compiler receives
//! typed statement-root geometry, never a prepared child witness or captured
//! preprocessing. Template-key admission must still pin this compiler input.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compiler = @import("incremental_ethereum_vm_composition_program_v4.zig");
const graph = @import("air/composition_circuit.zig");
const witness = @import("air/vm_air_composition_input_witness.zig");
const framework = @import("air/framework_interaction.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW: u8 = 18;
pub const COLUMN_COUNT = witness.PREPROCESSED_COLUMN_COUNT;

pub const Fixed = struct {
    preprocessing: witness.Preprocessed,
    graph_id: [32]u8,
    program_id: [32]u8,
    schedule_id: [32]u8,

    /// The caller must select this typed compiler input independently of the
    /// child proof. Claim aliases match the direct native SegmentV2 path.
    pub fn init(
        allocator: std.mem.Allocator,
        input: compiler.StatementRootCompilerInput,
    ) !Fixed {
        var retained: graph.CompiledSchedule = undefined;
        var program = try compiler.compileWithClaimAliasesRetainingSchedule(allocator, input, &retained);
        defer program.deinit();
        var preprocessing = try witness.Preprocessed.initTakingCompiled(&retained);
        errdefer preprocessing.deinit();
        if (!std.mem.eql(u8, &program.schedule_sha256, &preprocessing.authority_digest))
            return error.CompositionCompilerScheduleMismatchV6;
        return .{
            .preprocessing = preprocessing,
            .graph_id = program.graph_sha256,
            .program_id = program.verifier_program_authority,
            .schedule_id = program.schedule_sha256,
        };
    }

    pub fn deinit(self: *Fixed) void {
        self.preprocessing.deinit();
        self.* = undefined;
    }

    /// Cold verifier key check. Recompilation is intentional here: a cached
    /// schedule digest alone cannot authenticate caller-supplied graph inputs.
    pub fn validateAgainst(
        self: *const Fixed,
        allocator: std.mem.Allocator,
        input: compiler.StatementRootCompilerInput,
    ) !void {
        var rebuilt = try Fixed.init(allocator, input);
        defer rebuilt.deinit();
        if (!std.mem.eql(u8, &self.graph_id, &rebuilt.graph_id) or
            !std.mem.eql(u8, &self.program_id, &rebuilt.program_id) or
            !std.mem.eql(u8, &self.schedule_id, &rebuilt.schedule_id) or
            self.preprocessing.log_size != rebuilt.preprocessing.log_size or
            self.preprocessing.rows.len != rebuilt.preprocessing.rows.len)
            return error.CompositionGraphAuthorityMismatchV6;
        try self.preprocessing.validate();
    }

    pub fn writePhysical(self: *const Fixed, columns: [][]M31) !void {
        try self.preprocessing.validate();
        if (self.preprocessing.source != .authenticated_graph or
            !std.mem.eql(u8, &self.schedule_id, &self.preprocessing.authority_digest))
            return error.CompositionCompilerScheduleMismatchV6;
        if (columns.len != COLUMN_COUNT or self.preprocessing.log_size >= @bitSizeOf(usize))
            return error.CompositionColumnGeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(self.preprocessing.log_size);
        for (columns) |column| {
            if (column.len != capacity) return error.CompositionColumnGeometryMismatchV6;
            for (column) |value| if (!value.isZero())
                return error.CompositionDestinationNotFreshV6;
        }
        for (self.preprocessing.rows, 0..) |row, logical| {
            const values = row.values();
            const physical = framework.committedRow(logical, self.preprocessing.log_size);
            for (values, columns) |value, column| column[physical] = value;
        }
    }
};

test "V6 row18 physical columns match core writer for distinct same-shape statements" {
    const allocator = std.testing.allocator;
    const support = @import("ethereum_leaf_context_v1_test_support.zig");
    const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
    const profile_mod = @import("vm_air_profile_v2.zig");
    const base_geometry = @import("vm_composition_base_geometry_v2.zig");
    const extension_statement = @import("../air/guest_precompile/ethereum_statement.zig");
    const extension_geometry = @import("ethereum_composition_extension_geometry_v2.zig");
    const bridge = @import("../prover/incremental_bridge_external_v3.zig");
    const air = @import("air/vm_air_composition_input.zig");
    var first: ?[32]u8 = null;
    for ([_]u32{ 0, 4 }) |pc_delta| {
        var native = support.retainedSegmentZeroCore();
        native.initial_pc += pc_delta;
        native.final_pc += pc_delta;
        for (native.infra_descs[0..native.n_infra]) |*descriptor| if (descriptor.kind == .poseidon2) {
            descriptor.n_columns = @import("../air/memory_commitment/poseidon2_narrow_degree3_v1.zig").N_MAIN_COLUMNS;
        };
        const manifest = lookup.Manifest.native();
        const authenticated = try lookup.AuthenticatedStatement.init(&native, &manifest);
        const sample_count = try base_geometry.expectedSampledValueCountWithCircuitProfile(&native, &manifest, .fixed_program_narrow_v1);
        var profile = try profile_mod.deriveAuthorityWithCircuitProfile(allocator, &native, &manifest, &authenticated, sample_count, .fixed_program_narrow_v1);
        defer profile.deinit();
        const extension = try extension_statement.Statement.canonical(&native, 0, 0, support.emptySecpShapes());
        var extension_layout = try extension_geometry.GeometryV2.init(allocator, &profile, &native, &extension);
        defer extension_layout.deinit();
        const prefix: bridge.PrefixColumnsV3 = .{
            .preprocessed = @intCast(profile.preprocessed_column_count + extension_layout.columns[0].len + @import("../air/program/interaction.zig").FIXED_COLUMN_COUNT),
            .main = @intCast(profile.main_column_count + extension_layout.columns[1].len),
            .interaction = @intCast(profile.interaction_column_count + extension_layout.columns[2].len),
        };
        const input: compiler.StatementRootCompilerInput = .{
            .core_statement = &native,
            .extension_statement = &extension,
            .lookup_manifest = &manifest,
            .authenticated_lookup = &authenticated,
            .base_profile = &profile,
            .bridge_geometry = try bridge.GeometryV3.canonicalAfterPrefix(1, prefix),
        };
        var fixed = try Fixed.init(allocator, input);
        defer fixed.deinit();
        if (first) |digest| try std.testing.expectEqualDeep(digest, fixed.schedule_id) else first = fixed.schedule_id;
        var definition = try air.build(allocator);
        defer definition.deinit();
        const binding = try witness.Binding.canonical(&definition);
        const executor = try witness.Executor.init(&definition, &binding);
        const capacity = @as(usize, 1) << @intCast(fixed.preprocessing.log_size);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const physical = try a.alloc([]M31, COLUMN_COUNT);
        var raw: [COLUMN_COUNT][]M31 = undefined;
        for (physical, &raw) |*destination, *source| {
            destination.* = try a.alloc(M31, capacity);
            @memset(destination.*, M31.zero());
            source.* = try a.alloc(M31, capacity);
        }
        try fixed.writePhysical(physical);
        try fixed.validateAgainst(allocator, input);
        try executor.generatePreprocessedInto(&fixed.preprocessing, &raw);
        for (physical, raw) |destination, source| for (source, 0..) |expected, logical| {
            try std.testing.expectEqual(expected.toU32(), destination[framework.committedRow(logical, fixed.preprocessing.log_size)].toU32());
        };
        fixed.preprocessing.rows[0].use_count += 1;
        try std.testing.expectError(error.AuthorityMismatch, fixed.writePhysical(physical));
        fixed.preprocessing.rows[0].use_count -= 1;
        fixed.schedule_id[0] ^= 1;
        try std.testing.expectError(error.CompositionCompilerScheduleMismatchV6, fixed.writePhysical(physical));
        fixed.schedule_id[0] ^= 1;
        fixed.graph_id[0] ^= 1;
        try std.testing.expectError(error.CompositionGraphAuthorityMismatchV6, fixed.validateAgainst(allocator, input));
    }
}
