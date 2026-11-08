//! Exact native circuit LogUp representation; distinct from truth cumulative.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const S = @import("outer_source.zig");
const Prefix = @import("prefix_plan.zig");
const Abi = @import("abi.zig");
pub fn generate(owner: *S.Owner, raw: *anyopaque, token: u64) !void {
    var range = try @import("nvtx_stage.zig").Range.beginUnlessAdmitted(&owner.backend.service.library, raw, "rv64/recursion/INTER-witness", owner.permit != null);
    defer range.deinit();
    var ctx = owner.context(raw, token, owner.scope);
    defer ctx.active = false;
    const b = owner.backend;
    const a = owner.allocator;
    const reuse_inter = b.trace_commit.reusesInterInputs((try Outer.protocol.targetConfig()).fri_config.log_blowup_factor);
    const elements = Outer.witness.Elements.init(owner.z, owner.alpha);
    var parameter_words: [56]u32 = undefined;
    for (owner.z.toM31Array(), 0..) |m, i| parameter_words[i] = m.v;
    for (elements.powers, 0..) |p, i| for (p.toM31Array(), 0..) |m, j| {
        parameter_words[8 + 8 * i + j] = m.v;
    };
    var parameters = if (owner.device_fs_parameters) |lease| lease else try ctx.allocate(56, 0);
    defer if (owner.device_fs_parameters == null) ctx.release(&parameters) catch {};
    if (owner.device_fs_parameters == null) {
        try ctx.upload(try ctx.borrow(parameters), &parameter_words);
    } else {
        _ = try ctx.borrow(parameters);
        if (parameters.count != 56) return error.InvalidOuterDeviceFsParameters;
        std.debug.print("GPU_OUTER_DEVICE_FS inter_consumed ordinal={} parameter_words=56 host_parameter_upload_words=0\n", .{owner.scope.ordinal});
    }
    // M6 enqueue: every copy, clear and kernel of this stage is ordered on
    // lane 0 (the context stream, which also carries the staged uploads), so
    // no host join is needed between components. The eleven claims and the
    // shared status word (kernels only OR failure bits into it) live in one
    // lease and come back in ONE staged readback after the last component.
    // Kernel lane choice and readback batching cannot change any word.
    const component_count = 11;
    var results = try ctx.allocate(8 * component_count + 1, 0);
    defer ctx.release(&results) catch {};
    const status_word = results.words.? + 8 * component_count;
    try S.checked(b.clear(raw, status_word, 0, 4));
    var claims: [component_count]Outer.protocol.O = undefined;
    const kinds = std.enums.values(@import("stwo_circuit_frontend").common.component_list.ComponentList);
    const widths = @import("stwo_circuit_frontend").witness.trace.traceWidths();
    const Component = struct { log: u32, pairs: usize };
    var components: [component_count]Component = undefined;
    var main_offsets: [component_count]usize = undefined;
    var inter_offsets: [component_count]usize = undefined;
    var main_total: usize = 0;
    var inter_total: usize = 0;
    for (owner.key.logs.toArray(), kinds, widths, 0..) |log, kind, width, ci| {
        const pairs = (@import("stwo_circuit_frontend").witness.trace.RawLookupRows.count(kind) + 1) / 2;
        components[ci] = .{ .log = log, .pairs = pairs };
        main_offsets[ci] = main_total;
        inter_offsets[ci] = inter_total;
        main_total += width;
        inter_total += 8 * pairs;
    }
    if (inter_total != owner.inter_columns.len or main_total != owner.main_columns.len) return error.InvalidCircuitInteractionRoster;
    const layout = if (reuse_inter) try @import("trace_input_reuse.zig").Layout.init(&components) else null;
    const packed_output = if (layout) |value| try owner.ownedKind(&ctx, try value.words(), 2) else null;
    if (layout) |value| std.debug.print("GPU_INTER_PACKED ordinal={} logical_words={} tail_words={} allocation_words={} sorted_coefficient_prefix=true\n", .{ owner.scope.ordinal, value.logical_words, value.tail_words, try value.words() });
    for (0..component_count) |position| {
        const ci = if (layout) |value| value.order[position] else position;
        const log = components[ci].log;
        const width = widths[ci];
        const rows = @as(usize, 1) << @intCast(log);
        const pairs = components[ci].pairs;
        const main_at = main_offsets[ci];
        const inter_at = inter_offsets[ci];
        const indices = try S.lookupIndices(a, owner.key, ci);
        defer a.free(indices);
        var fixed = try ctx.allocate(@max(@as(usize, 1), indices.len * rows), 0);
        defer ctx.release(&fixed) catch {};
        // Gather only immutable table/gate columns. The canonical tuple order
        // differs from the captured AIR read order, especially for BlakeG.
        for (indices, 0..) |index, i| {
            const source = owner.raw_fixed[index];
            if (source.count != rows) return error.InvalidCircuitLookupGeometry;
            try S.checked(b.service.lease_validate_range(b.service.session, source.words.?, source.count, source.context_token, source.generation, &@import("pcs_scope.zig").identity(owner.initial_scope)));
            try S.checked(b.copy(raw, @ptrCast(fixed.words.? + i * rows), @ptrCast(source.words.?), rows * 4));
        }
        const output = packed_output orelse try owner.owned(&ctx, 8 * (pairs + 1) * rows);
        const output_words = output.words.? + (if (layout) |value| value.offsets[ci] else 0);
        // The cumulative-prefix scratch follows this component's live columns.
        // Physical-order generation lets it use only the unwritten suffix or
        // the final tail, never an earlier component's completed evaluations.
        var numerators: ?@import("pcs_native_abi.zig").Lease = if (b.inter_contributions == null) try ctx.allocate(8 * pairs * rows, 0) else null;
        defer if (numerators) |*lease| ctx.release(lease) catch {};
        const prefix = try Prefix.Plan.init(log);
        var scratch = try ctx.allocate(prefix.scratch_words, 0);
        defer ctx.release(&scratch) catch {};
        const claim_words = results.words.? + 8 * ci;
        const source_scope = @import("pcs_scope.zig").identity(owner.initial_scope);
        for (owner.main_columns[main_at..][0..width]) |column| {
            const input = column.device orelse return error.MissingOuterDeviceMain;
            if (column.log_size != log or input.count != rows) return error.InvalidCircuitLookupGeometry;
            try S.checked(b.service.lease_validate_range(b.service.session, input.words, input.count, input.context_token, input.generation, &source_scope));
        }
        const first = owner.main_columns[main_at].device.?;
        const contributions = if (numerators) |lease| lease.words.? else output_words;
        if (b.inter_contributions) |kernels| {
            const job = S.Contributions{ .fixed = fixed.words.?, .main = first.words, .parameters = parameters.words.?, .output = output_words, .status = @ptrCast(status_word), .fixed_words = indices.len * rows, .main_words = width * rows, .output_words = 8 * pairs * rows, .component = @intCast(ci), .row_log = log };
            try S.checked(kernels.generate(raw, 0, &job));
        } else {
            const job = S.Fractions{ .fixed = fixed.words.?, .main = first.words, .parameters = parameters.words.?, .numerators = contributions, .denominators = output_words, .status = @ptrCast(status_word), .fixed_words = indices.len * rows, .main_words = width * rows, .numerator_words = 8 * pairs * rows, .denominator_words = 8 * pairs * rows, .component = @intCast(ci), .row_log = log };
            try S.checked(b.fractions(raw, 0, &job));
        }
        const global = Abi.GlobalPairs{ .output = output_words, .contributions = contributions, .scan_scratch = scratch.words.?, .claim = claim_words, .status = @ptrCast(status_word), .stride = rows, .scan_words = prefix.scratch_words, .row_log = log, .pairs = @intCast(pairs) };
        try S.checked(if (b.inter_contributions) |kernels| kernels.scan(raw, 0, &global) else b.global_pairs(raw, 0, &global));
        const cumulative = S.Cumulative{ .output = output_words, .contributions = contributions, .claim = claim_words, .stride = rows, .row_log = log, .pairs = @intCast(pairs) };
        try S.checked(if (b.inter_contributions) |kernels| kernels.cumulative(raw, 0, &cumulative) else b.cumulative(raw, 0, &cumulative));
        if (b.inter_contributions != null) std.debug.print("GPU_INTER_CONTRIBUTIONS ordinal={} component={} rows={} pairs={} numerator_words=0 legacy_numerator_words={} exact_alias=true\n", .{ owner.scope.ordinal, ci, rows, pairs, 8 * pairs * rows });
        // fixed/numerators/scratch are released at the end of this iteration
        // while lane 0 still reads them: an arena range is fenced on the
        // device (reuse waits on lane 0), a pool range is host-joined by free.
        for (0..8 * pairs) |i| owner.inter_columns[inter_at + i] = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = output_words + i * rows, .count = rows, .context_token = token, .generation = output.generation } };
    }
    // One staged D2H on lane 0: data is present on return and ordered after
    // every kernel above. The join then finds idle lanes (no driver sync).
    var words: [8 * component_count + 1]u32 = undefined;
    try ctx.download(try ctx.borrow(results), &words);
    try ctx.join();
    if (words[8 * component_count] != 0) return error.InvalidCircuitDeviceInteraction;
    for (&claims, 0..) |*claim, ci| {
        var coordinates: [8]Outer.protocol.M = undefined;
        for (&coordinates, words[8 * ci ..][0..8]) |*out, word| {
            if (word >= @import("stwo_core").fields.m31.Modulus) return error.NoncanonicalOuterClaim;
            out.* = Outer.protocol.M.fromCanonical(word);
        }
        claim.* = Outer.protocol.O.fromM31Array(coordinates);
    }
    owner.claims = Outer.witness.Claims.fromArray(claims);
}
