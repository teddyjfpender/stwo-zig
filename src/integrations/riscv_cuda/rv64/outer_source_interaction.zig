//! Exact native circuit LogUp representation; distinct from truth cumulative.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const S = @import("outer_source.zig");
const Prefix = @import("prefix_plan.zig");
const Abi = @import("abi.zig");
pub fn generate(owner: *S.Owner, raw: *anyopaque, token: u64) !void {
    var ctx = owner.context(raw, token, owner.scope);
    defer ctx.active = false;
    const b = owner.backend;
    const a = owner.allocator;
    const elements = Outer.witness.Elements.init(owner.z, owner.alpha);
    var parameter_words: [56]u32 = undefined;
    for (owner.z.toM31Array(), 0..) |m, i| parameter_words[i] = m.v;
    for (elements.powers, 0..) |p, i| for (p.toM31Array(), 0..) |m, j| {
        parameter_words[8 + 8 * i + j] = m.v;
    };
    var parameters = try ctx.allocate(56, 0);
    defer ctx.release(&parameters) catch {};
    try ctx.upload(try ctx.borrow(parameters), &parameter_words);
    var claims: [11]Outer.protocol.O = undefined;
    var main_at: usize = 0;
    var inter_at: usize = 0;
    const kinds = std.enums.values(@import("stwo_circuit_frontend").common.component_list.ComponentList);
    const widths = @import("stwo_circuit_frontend").witness.trace.traceWidths();
    for (owner.key.logs.toArray(), kinds, widths, 0..) |log, kind, width, ci| {
        const rows = @as(usize, 1) << @intCast(log);
        const pairs = (@import("stwo_circuit_frontend").witness.trace.RawLookupRows.count(kind) + 1) / 2;
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
        const output = try owner.owned(&ctx, 8 * (pairs + 1) * rows);
        var numerators = try ctx.allocate(8 * pairs * rows, 0);
        defer ctx.release(&numerators) catch {};
        const prefix = try Prefix.Plan.init(log);
        var scratch = try ctx.allocate(prefix.scratch_words, 0);
        defer ctx.release(&scratch) catch {};
        var claim = try ctx.allocate(8, 0);
        defer ctx.release(&claim) catch {};
        var status = try ctx.allocate(1, 0);
        defer ctx.release(&status) catch {};
        try S.checked(b.clear(raw, status.words.?, 0, 4));
        try ctx.join();
        const source_scope = @import("pcs_scope.zig").identity(owner.initial_scope);
        for (owner.main_columns[main_at..][0..width]) |column| {
            const input = column.device orelse return error.MissingOuterDeviceMain;
            if (column.log_size != log or input.count != rows) return error.InvalidCircuitLookupGeometry;
            try S.checked(b.service.lease_validate_range(b.service.session, input.words, input.count, input.context_token, input.generation, &source_scope));
        }
        const first = owner.main_columns[main_at].device.?;
        const job = S.Fractions{ .fixed = fixed.words.?, .main = first.words, .parameters = parameters.words.?, .numerators = numerators.words.?, .denominators = output.words.?, .status = @ptrCast(status.words.?), .fixed_words = indices.len * rows, .main_words = width * rows, .numerator_words = 8 * pairs * rows, .denominator_words = 8 * pairs * rows, .component = @intCast(ci), .row_log = log };
        try S.checked(b.fractions(raw, 1, &job));
        const global = Abi.GlobalPairs{ .output = output.words.?, .contributions = numerators.words.?, .scan_scratch = scratch.words.?, .claim = claim.words.?, .status = @ptrCast(status.words.?), .stride = rows, .scan_words = prefix.scratch_words, .row_log = log, .pairs = @intCast(pairs) };
        try S.checked(b.global_pairs(raw, 1, &global));
        const cumulative = S.Cumulative{ .output = output.words.?, .contributions = numerators.words.?, .claim = claim.words.?, .stride = rows, .row_log = log, .pairs = @intCast(pairs) };
        try S.checked(b.cumulative(raw, 1, &cumulative));
        try ctx.join();
        var flag: [1]u32 = undefined;
        var words: [8]u32 = undefined;
        try ctx.download(try ctx.borrow(status), &flag);
        try ctx.download(try ctx.borrow(claim), &words);
        try ctx.join();
        if (flag[0] != 0) return error.InvalidCircuitDeviceInteraction;
        var coordinates: [8]Outer.protocol.M = undefined;
        for (&coordinates, words) |*out, word| {
            if (word >= @import("stwo_core").fields.m31.Modulus) return error.NoncanonicalOuterClaim;
            out.* = Outer.protocol.M.fromCanonical(word);
        }
        claims[ci] = Outer.protocol.O.fromM31Array(coordinates);
        for (0..8 * pairs) |i| owner.inter_columns[inter_at + i] = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = output.words.? + i * rows, .count = rows, .context_token = token, .generation = output.generation } };
        main_at += width;
        inter_at += 8 * pairs;
    }
    if (inter_at != owner.inter_columns.len or main_at != owner.main_columns.len) return error.InvalidCircuitInteractionRoster;
    owner.claims = Outer.witness.Claims.fromArray(claims);
}
