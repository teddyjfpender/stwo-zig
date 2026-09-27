//! Real independent shape/catalogue/source admissions; no proof or capture is
//! manufactured. Store construction and pins alone convey no proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Selection = @import("block_v5_native_fused_recursive_selection_v1.zig");
const Native = @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Frame = @import("../air/block/memory_event.zig").Frame;
const Seal = @import("block_v5_source_seal_v1.zig");
const Stores = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const T = Stores.ForFamily(.native_capacity_fused);
const C = T.Codec;
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Q = core.fields.qm31.QM31;

fn shape(empty: bool) Shape {
    var result = std.mem.zeroes(Shape);
    result.initializeDescriptorStorage();
    const rows: u32 = if (empty) 3 else 5;
    if (!empty) {
        result.n_components = 1;
        result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = 3, .n_rows = rows, .n_columns = @intCast(@import("../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
        result.n_infra = 1;
        result.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 2, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
    }
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}

const Fixture = struct {
    shapes: [2]Shape,
    templates: [2]Capacity.Template,
    records: [2]Catalog.Record,
    public: [2]Public.Admission,
    external: [2]u32,
    entries: [8]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init(a: std.mem.Allocator, both_empty: bool) !Fixture {
        var out: Fixture = undefined;
        out.shapes = .{ shape(true), shape(both_empty) };
        out.external = .{ 3, if (both_empty) 3 else 0 };
        out.entries[0] = .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } };
        var first: u64 = 1;
        for (0..2) |i| {
            const s = &out.shapes[i];
            out.templates[i] = try Capacity.Template.fromShape(s, out.external[i], Parent.CSP_CONFIG, .rv32im_zkvm_v1, @splat(4));
            out.records[i] = try Catalog.Record.fromTemplate(@intCast(i), out.templates[i]);
            out.public[i] = try Public.Admission.init(.{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = @intCast(i), .first_cycle = first, .last_cycle = first + s.total_steps - 1 }, &s.public_data);
            const roots: Seal.Roots = .{ out.templates[i].fixed_root, @splat(20) };
            const execution = Seal.Entry{ .family = .execution, .index = @intCast(i), .instance_id = try Capacity.instanceId(out.records[i].template_id, s, out.external[i], out.public[i], roots, @intCast(i)), .roots = roots };
            out.entries[1 + i] = execution;
            const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = first, .cycle_count = s.public_data.clock };
            const projections = try Source.slotsFromShapeForMode(a, s, out.external[i], 0);
            defer a.free(projections);
            const slots = try Source.memorySlots(a, s, out.external[i], frame, 0);
            defer a.free(slots);
            const witness: [32]u8 = if (slots.len == 0) try Source.emptyWitnessRoot(0) else @splat(21);
            out.entries[3 + i] = if (slots.len == 0)
                try Source.emptyEntry(a, s, out.external[i], frame, execution, 0, 0)
            else
                Memory.packedEntry(execution.instance_id, execution.roots, witness, @intCast(i), slots);
            out.entries[5 + i] = Fused.entry(out.records[i].template_id, execution.instance_id, roots, witness, @intCast(i), frame, projections, slots);
            first += s.total_steps;
        }
        out.entries[7] = .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (out.entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        out.pins = .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try (Catalog.Admission{ .records = &out.records }).digest(), .config = Parent.CSP_CONFIG, .counts = counts };
        out.sealed = try Seal.seal(out.pins, &out.entries);
        return out;
    }
    fn roster(self: *const Fixture) Stores.Roster {
        return .{ .sealed = self.sealed, .pins = self.pins, .entries = &self.entries };
    }
    fn native(self: *const Fixture, a: std.mem.Allocator, index: usize) !Native {
        return Native.init(a, &self.shapes[index], self.external[index], self.public[index], self.templates[index], self.records[index].template_id, @intCast(index), self.sealed, self.pins, &self.entries, .{ .records = &self.records }, .{});
    }
    fn fused(self: *const Fixture, a: std.mem.Allocator, native_policy: *const Native) !C.Admission.Prepared {
        const index = native_policy.index;
        const execution = self.entries[1 + index];
        const proposal = @import("block_v5_native_capacity_proof_v1.zig").OpenReceipt{ .template_id = native_policy.template_id, .instance_id = execution.instance_id, .first_roots = execution.roots, .sealed_digest = self.sealed.digest, .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(native_policy.shape, native_policy.external_retirements), .open_sum = Q.zero() };
        return C.Admission.Prepared.init(a, native_policy, proposal, .{ .clock_frame = .leaf_local, .global_first_cycle = native_policy.pin.context.first_cycle, .cycle_count = native_policy.shape.public_data.clock }, @splat(21), .{});
    }
};
const wires = [_]C.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .source = .first_root, .coordinate = 0 }};
fn template(prepared: *const C.Admission.Prepared) !C.Template {
    const geometry = Parent.Key{ .profile = .csp_q70_pow26, .config = prepared.config, .context = .{ .child_key_id = prepared.template_id, .child_config = prepared.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try C.Protocol.Key.fromGeometry(geometry, &wires);
    return .{ .key = key, .key_id = try key.identity(), .schedule = &wires };
}

test "native fused selection: genuine empty first execution selects only required companion and preserves dense defaults" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a, false);
    var first = try fixture.native(a, 0);
    defer first.deinit();
    var second = try fixture.native(a, 1);
    defer second.deinit();
    var selected = try Selection.Selection.init(a, fixture.roster(), &.{ &first, &second }, .{});
    defer selected.deinit();
    try std.testing.expectEqualSlices(u32, &.{1}, selected.indices);
    var fused = try fixture.fused(a, &second);
    defer fused.deinit();
    const key = try template(&fused);
    const policy = C.Policy{ .prepared = &fused, .template = &key };
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try std.testing.expectError(error.IncompleteRecursiveExecutionPolicies, T.Store.initWriter(a, dir.dir, fixture.roster(), &.{policy}, .{}));
    var writer = try T.Store.initWriterWithSelection(a, dir.dir, fixture.roster(), &.{policy}, &selected, .{});
    defer writer.deinit();
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, writer.filePins(a));
    const pins = [_]Stores.FilePin{.{ .index = 1, .byte_len = 100, .sha256 = @splat(1) }};
    try std.testing.expectError(error.UntrustedRecursiveExecutionFilePin, T.validatePins(&pins, .{}));
    var reader = try T.Store.initReaderWithSelection(a, dir.dir, fixture.roster(), &.{policy}, &pins, &selected, .{});
    defer reader.deinit();
    try std.testing.expectError(error.IncompleteRecursiveExecutionVerification, reader.requireVerified());
    try std.testing.expectError(error.UnadmittedRecursiveExecutionIndex, reader.proofBytes(a, 0));
    var relabeled = pins;
    relabeled[0].index = 0;
    try std.testing.expectError(error.UntrustedRecursiveExecutionFileIndex, T.Store.initReaderWithSelection(a, dir.dir, fixture.roster(), &.{policy}, &relabeled, &selected, .{}));
    try std.testing.expectError(error.IncompleteRecursiveExecutionFiles, T.Store.initReaderWithSelection(a, dir.dir, fixture.roster(), &.{policy}, &.{}, &selected, .{}));
    try std.testing.expectError(error.IncompleteRecursiveExecutionPolicies, T.Store.initWriterWithSelection(a, dir.dir, fixture.roster(), &.{}, &selected, .{}));
    const independent_copy = second;
    var copied_fused = fused;
    copied_fused.native = &independent_copy;
    const copied_policy = C.Policy{ .prepared = &copied_fused, .template = &key };
    try std.testing.expectError(error.UntrustedRecursiveExecutionRoster, T.Store.initWriterWithSelection(a, dir.dir, fixture.roster(), &.{copied_policy}, &selected, .{}));
}

test "native fused selection: retained omissions relabels reordered native owners and changed original geometry fail closed" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a, false);
    var first = try fixture.native(a, 0);
    defer first.deinit();
    var second = try fixture.native(a, 1);
    defer second.deinit();
    var selected = try Selection.Selection.init(a, fixture.roster(), &.{ &first, &second }, .{});
    defer selected.deinit();
    const indices = selected.indices;
    selected.indices = indices[0..0];
    try std.testing.expectError(error.UntrustedNativeFusedSelection, selected.require(fixture.roster()));
    selected.indices = indices;
    selected.storage[0] = 0;
    try std.testing.expectError(error.UntrustedNativeFusedSelection, selected.require(fixture.roster()));
    selected.storage[0] = 1;
    std.mem.swap(*const Native, &selected.natives[0], &selected.natives[1]);
    try std.testing.expectError(error.UntrustedNativeFusedSelectionRoster, selected.require(fixture.roster()));
    std.mem.swap(*const Native, &selected.natives[0], &selected.natives[1]);
    const log = second.logs[1][0];
    second.logs[1][0] += 1;
    try std.testing.expectError(error.UntrustedNativeCapacityRecursiveGeometry, selected.require(fixture.roster()));
    second.logs[1][0] = log;
    const config = second.config;
    second.config.pow_bits = 0;
    try std.testing.expectError(error.UntrustedNativeCapacityRecursiveAdmission, selected.require(fixture.roster()));
    second.config = config;
    try selected.require(fixture.roster());
}

test "native fused selection: actual all-empty native roster needs no fused files and grants no leaf authority" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a, true);
    var first = try fixture.native(a, 0);
    defer first.deinit();
    var second = try fixture.native(a, 1);
    defer second.deinit();
    var selected = try Selection.Selection.init(a, fixture.roster(), &.{ &first, &second }, .{});
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 0), selected.indices.len);
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var writer = try T.Store.initWriterWithSelection(a, dir.dir, fixture.roster(), &.{}, &selected, .{});
    defer writer.deinit();
    const pins = try writer.filePins(a);
    defer a.free(pins);
    try std.testing.expectEqual(@as(usize, 0), pins.len);
    var reader = try T.Store.initReaderWithSelection(a, dir.dir, fixture.roster(), &.{}, pins, &selected, .{});
    defer reader.deinit();
    try reader.requireVerified(); // Empty census only; no returned equation.
    try std.testing.expectError(error.UnadmittedRecursiveExecutionIndex, reader.takeFresh(0));
}

fn selectionAllocations(a: std.mem.Allocator, roster: Stores.Roster, natives: []const *const Native) !void {
    var selected = try Selection.Selection.init(a, roster, natives, .{});
    defer selected.deinit();
    try selected.require(roster);
}
test "native fused selection: limits reject before allocation and every partial selection unwinds" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a, false);
    var first = try fixture.native(a, 0);
    defer first.deinit();
    var second = try fixture.native(a, 1);
    defer second.deinit();
    var denied = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.NativeFusedSelectionResourceLimit, Selection.Selection.init(denied.allocator(), fixture.roster(), &.{ &first, &second }, .{ .max_executions = 1 }));
    try std.testing.expectError(error.NativeFusedSelectionResourceLimit, Selection.Selection.init(denied.allocator(), fixture.roster(), &.{ &first, &second }, .{ .max_metadata_bytes = 1 }));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
    try std.testing.expectError(error.IncompleteNativeFusedSelection, Selection.Selection.init(a, fixture.roster(), &.{&first}, .{}));
    try std.testing.checkAllAllocationFailures(a, selectionAllocations, .{ fixture.roster(), @as([]const *const Native, &.{ &first, &second }) });
}
