//! Program-request source identity for the future same-native-root v5 sidecar.
//! This borrows the production typed opcode relation builder. It grants no
//! proof authority until a PCS quotient reads the same committed main columns.
const std = @import("std");
const entries = @import("../air/lookups/opcode_entries.zig");
const trace = @import("../runner/trace.zig");
const geometry = @import("../air/statement_geometry.zig");

pub fn Request(comptime S: type) type {
    return struct { numerator: S, tuple: [5]S };
}

/// Every admitted native opcode row has exactly one canonical fetch request.
/// `main` must come from the native proof's original fixed/main PCS openings.
pub fn fromCommittedOpcodeMain(comptime S: type, family: trace.OpcodeFamily, main: []const S) !Request(S) {
    if (main.len != trace.nColumnsForFamily(family)) return error.InvalidProgramRequestMainGeometry;
    const list = try entries.Entries(S).fromMain(family, main);
    var result: ?Request(S) = null;
    for (list.entries[0..list.len]) |entry| {
        if (entry.domain != .program_access) continue;
        if (result != null or entry.role != .request or entry.arity != 5)
            return error.InvalidProgramRequestRoster;
        result = .{ .numerator = entry.numerator, .tuple = entry.values[0..5].* };
    }
    return result orelse error.MissingProgramRequest;
}

/// Independently pinned native component geometry supplies this integer
/// census. The v5 PCS sidecar must prove its request selectors match it.
pub fn exactOpcodeFetchCount(descs: []const geometry.FamilyComponentDesc) !u64 {
    var total: u64 = 0;
    for (descs) |desc| {
        if (desc.log_size > 24 or desc.n_rows > (@as(u32, 1) << @intCast(desc.log_size)))
            return error.InvalidProgramRequestGeometry;
        total = try std.math.add(u64, total, desc.n_rows);
    }
    return total;
}

test "v5 program request source covers every native opcode family once" {
    const core = @import("stwo_core");
    const Q = core.fields.qm31.QM31;
    const main: [trace.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const request = try fromCommittedOpcodeMain(Q, family, main[0..trace.nColumnsForFamily(family)]);
        try std.testing.expect(request.numerator.isZero());
    }
    const descs = [_]geometry.FamilyComponentDesc{
        .{ .family = .lui, .log_size = 7, .n_rows = 3 },
        .{ .family = .jal, .log_size = 7, .n_rows = 5 },
    };
    try std.testing.expectEqual(@as(u64, 8), try exactOpcodeFetchCount(&descs));
}
