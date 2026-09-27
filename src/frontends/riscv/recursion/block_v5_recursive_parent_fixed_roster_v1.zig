//! Capture-free ORIGINAL parent verifier row roster. Exact fixed source order,
//! original fusion/partition/projection; no physical-main columns or Verified.
//! This does not contain enclosing closed-node graph/public boundary attachments
//! and therefore cannot emit an expected closed-node key or block authority.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const PiecesModule = @import("block_v5_recursive_parent_fixed_pieces_v1.zig");
const AssemblyModule = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const SourcePortsModule = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig");
const PackedPorts = @import("air/block_v5_requester_recursive_packed_fixed_v1.zig");
const Openings = @import("air/block_v5_recursive_parent_fixed_openings_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Projection = @import("air/blake3_row_columns.zig");
const Direct = @import("air/blake3_direct_cohort_columns_v1.zig");
const NativeFusion = @import("air/native_pcs_fusion_rows.zig");
const Partition = @import("air/blake3_g_partition.zig");
const M = @import("stwo_core").fields.m31.M31;
const Builder = struct {
    a: std.mem.Allocator,
    fixed: Storage.FixedTuple(true),
    fn init(a: std.mem.Allocator) Builder {
        var result = Builder{ .a = a, .fixed = undefined };
        inline for (0..Storage.Airs.len) |i| result.fixed[i] = .empty;
        return result;
    }
    fn append(self: *Builder, comptime slot: usize, rows: []const Storage.FixedRow(Storage.Airs[slot])) !void {
        _ = try Direct.rowLog(try std.math.add(usize, self.fixed[slot].items.len, rows.len));
        try self.fixed[slot].appendSlice(self.a, rows);
    }
    fn group(self: *Builder, source: anytype, comptime slots: anytype) !void {
        inline for (slots) |slot| try self.append(slot, try source.metadata(slot));
    }
    fn deinit(self: *Builder) void {
        inline for (0..Storage.Airs.len) |i| self.fixed[i].deinit(self.a);
    }
    fn partition(self: *Builder) !void {
        const geometry = try Partition.geometry(self.fixed[0].items.len);
        inline for (Partition.SHARDS[1..]) |slot| if (self.fixed[slot].items.len != 0) return error.InvalidNativeParentRows;
        // Allocate every replacement first; a failure preserves the source.
        var replacement: [Partition.SHARDS.len][]Storage.FixedRow(Storage.Airs[0]) = @splat(&.{});
        errdefer for (replacement) |rows| self.a.free(rows);
        var offset: usize = 0;
        for (geometry.counts, 0..) |count, i| {
            replacement[i] = try self.a.dupe(Storage.FixedRow(Storage.Airs[0]), self.fixed[0].items[offset..][0..count]);
            offset += count;
        }
        inline for (Partition.SHARDS, 0..) |slot, i| {
            self.fixed[slot].deinit(self.a);
            self.fixed[slot] = std.ArrayList(Storage.FixedRow(Storage.Airs[slot])).fromOwnedSlice(replacement[i]);
        }
    }
};
/// One original verifier fixed append/fusion/partition recipe for both original
/// parent and native word families. Structural routing only; typed wrappers
/// independently authenticate every source owner before building expected keys.
pub fn compileOriginalRoster(a: std.mem.Allocator, sources: anytype, packed_input: ?*const PackedPorts.Owned, openings: *const Openings.Owned, pcs: *const @import("air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig").Owned, plan: *const @import("air/blake3_transcript_plan.zig").Plan, paths: *const @import("air/blake3_stark_paths.zig").FixedShape, arithmetic: *const AssemblyModule.Arithmetic, selectors: [2]Storage.FixedRow(@import("air/blake3_boundary.zig")), dg: *const @import("air/pcs_deep_circuit.zig").Circuit) !Storage.FixedTuple(false) {
    @setEvalBranchQuota(10_000);
    var b = Builder.init(a);
    defer b.deinit();
    // Exact appendSources/appendSelectorInputs order from original rows.
    try b.group(&sources.challenges, .{ 12, 11 });
    try b.group(&sources.claims, .{ 12, 11 });
    if (packed_input) |ports| try b.group(&ports.rows, .{ 12, 11 });
    try b.group(&sources.samples, .{ 12, 11 });
    try b.group(&pcs.answer_rows, .{12});
    try b.group(&pcs.query_rows, .{12});
    try b.group(&openings.rows, .{12});
    try b.group(&sources.roots, .{ 2, 9 });
    try b.group(&sources.payload_bytes, .{10});
    try b.group(&pcs.query_rows, .{10});
    try b.group(&openings.rows, .{11});
    try b.group(&pcs.projection.rows, .{11});
    try b.group(&openings.rows, .{ 10, 16, 17 });
    try b.group(&sources.terminal, .{ 12, 11, 10 });
    const transcript = &plan.fixed;
    const hash = transcript.hash_metadata orelse return error.InvalidNativeParentRows;
    try b.append(0, hash.g_rows);
    try b.append(1, hash.xor_rows);
    const nonhash = if (transcript.nonhash_fixed) |*fixed| fixed else return error.InvalidNativeParentRows;
    inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| try b.append(slot, try nonhash.rows(slot));
    try b.append(0, paths.metadata.g_rows);
    try b.append(1, paths.metadata.xor_rows);
    try b.append(2, try paths.nonhash.rows(2));
    try b.group(&openings.rows, .{2});
    try b.append(7, try paths.nonhash.rows(7));
    try b.group(&pcs.projection.rows, .{7});
    try b.append(9, try paths.nonhash.rows(9));
    try b.append(13, try paths.nonhash.rows(13));
    try b.append(2, &selectors);
    const fused = &arithmetic.fused;
    var native = try NativeFusion.materializeFixed(a, dg, fused.fixed[0], b.fixed[12].items);
    defer native.deinit();
    // Preserve original scalar filtering and native/opening cohort order.
    b.fixed[12].clearRetainingCapacity();
    try b.append(12, native.scalars);
    try b.append(18, native.opening);
    try b.append(19, native.native);
    inline for (.{ 3, 4, 5 }, 1..) |slot, index| try b.append(slot, fused.fixed[index]);
    try b.append(2, arithmetic.boundaries);
    try b.partition();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
    inline for (0..Storage.Airs.len) |i| fixed[i] = try b.fixed[i].toOwnedSlice(a);
    return fixed;
}
pub fn ForAdmission(comptime Admission: type) type {
    return ForAdmissionMode(Admission, false);
}
/// Additive typed factory; old ForAdmission retains its public-input rejection.
pub fn ForPackedAdmission(comptime Admission: type) type {
    return ForAdmissionMode(Admission, true);
}
fn ForAdmissionMode(comptime Admission: type, comptime packed_public: bool) type {
    comptime if (!@hasDecl(Admission, "fixed_setup_only") or !Admission.fixed_setup_only) @compileError("fixed compiler requires independently reconstructed setup-only admission");
    return struct {
        const Pieces = PiecesModule.ForAdmission(Admission);
        const Assembly = AssemblyModule.ForAdmission(Admission);
        const SourcePorts = if (packed_public) SourcePortsModule.ForPackedPieces(Pieces.Owned) else SourcePortsModule.ForPieces(Pieces.Owned);
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            fixed: Storage.FixedTuple(false),
            logs: [Storage.Airs.len]u32,
            columns: []Column,
            shape_id: [32]u8,
            graph_ids: [3][32]u8,
            transcript_id: [32]u8,
            pub const complete_verifier_fixed_roster = true;
            pub const complete_closed_node_setup = false;
            pub const reusable_across_instances = false;
            pub const complete_block_authority = false;
            /// Independent entrypoint: reconstruct every piece from admitted policy,
            /// without accepting a received fixed roster or proof-derived capture.
            pub fn derive(a: std.mem.Allocator, admission: *const Admission, retry_capacity: u32, limits: Pieces.Limits) !*Self {
                const pieces = try Pieces.Owned.init(a, admission, retry_capacity, limits);
                defer pieces.deinit();
                const result = try Self.init(a, pieces, admission);
                errdefer result.deinit();
                try admission.validate();
                return result;
            }
            pub fn init(a: std.mem.Allocator, pieces: *const Pieces.Owned, admission: *const Admission) !*Self {
                // Static expansion of the original 23-cohort projection and
                // failure cleanup; this does not change runtime row limits.
                @setEvalBranchQuota(20_000);
                try pieces.validateAgainst(admission);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                const assembly = try Assembly.Owned.init(a, pieces, admission);
                defer assembly.deinit();
                const sources = try SourcePorts.Owned.init(a, pieces, admission.key.preprocessed_root);
                defer sources.deinit();
                var packed_ports: if (packed_public) PackedPorts.Owned else void = if (packed_public) try PackedPorts.Owned.init(a, pieces.composition, admission.source.terms, .{}) else {};
                defer if (packed_public) packed_ports.deinit();
                const openings = try Openings.Owned.init(a, pieces.shape, &pieces.arithmetic.deep_graph, &pieces.arithmetic.fri_graph, &pieces.paths, &assembly.pcs.projection);
                defer openings.deinit();
                const fixed = try compileOriginalRoster(a, sources, if (packed_public) &packed_ports else null, openings, assembly.pcs, &pieces.transcript.fixed, &pieces.paths, &assembly.arithmetic, assembly.selectors, &pieces.arithmetic.deep_graph);
                errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
                var logs: [Storage.Airs.len]u32 = undefined;
                var columns: std.ArrayList(Column) = .empty;
                errdefer {
                    for (columns.items) |column| a.free(column.values);
                    columns.deinit(a);
                }
                inline for (Storage.Airs, 0..) |Air, i| {
                    logs[i] = try Direct.rowLog(fixed[i].len);
                    try Projection.projectFixed(Air, a, fixed[i], logs[i], &columns);
                }
                // Same fixed lookup columns after all original AIR components.
                for ([_]@import("../air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try Projection.tablePreprocessed(a, kind, &columns);
                const owned_columns = try columns.toOwnedSlice(a);
                self.* = .{ .allocator = a, .lease = lease, .fixed = fixed, .logs = logs, .columns = owned_columns, .shape_id = pieces.shape.seal, .graph_ids = assembly.graph_ids, .transcript_id = assembly.transcript_id };
                return self;
            }
            /// Cold independent policy reconstruction. A resealed/mutated output is
            /// not expected-key authority; compare all actual fixed cells and contexts.
            pub fn validateAgainst(self: *const Self, admission: *const Admission, retry_capacity: u32, limits: Pieces.Limits) !void {
                const expected = try Self.derive(self.allocator, admission, retry_capacity, limits);
                defer expected.deinit();
                if (!std.meta.eql(self.logs, expected.logs) or !std.meta.eql(self.shape_id, expected.shape_id) or !std.meta.eql(self.graph_ids, expected.graph_ids) or !std.meta.eql(self.transcript_id, expected.transcript_id) or self.columns.len != expected.columns.len) return error.UntrustedRecursiveParentFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != expected.fixed[i].len) return error.UntrustedRecursiveParentFixedRoster;
                    for (self.fixed[i], expected.fixed[i]) |actual, retained| if (!std.meta.eql(actual, retained)) return error.UntrustedRecursiveParentFixedRoster;
                }
                for (self.columns, expected.columns) |actual, retained| {
                    if (actual.log_size != retained.log_size or actual.values.len != retained.values.len) return error.UntrustedRecursiveParentFixedRoster;
                    for (actual.values, retained.values) |left, right| if (!left.eql(right)) return error.UntrustedRecursiveParentFixedRoster;
                }
            }
            pub fn requireClosedNodeSetup(_: *const Self) error{MissingRecursiveParentFixedAttachments}!void {
                return error.MissingRecursiveParentFixedAttachments;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.lease;
                inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
                for (self.columns) |column| a.free(column.values);
                a.free(self.columns);
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
const Default = ForAdmission(@import("block_v5_closed_input_request_shape_admission_v1.zig").Admission);
pub const Owned = Default.Owned;
