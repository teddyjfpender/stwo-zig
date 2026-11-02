//! V3 CPU byte-pair queries and durable table metadata. A receiver-derived
//! geometry selects the mode; V2 defaults and its9 namespace draws stay exact.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const Fns = @import("fractions.zig");
pub fn cpuTerms(pairs: bool) u32 {
    return if (pairs) 14 else 15;
}
pub fn andTerms(pairs: bool) u32 {
    return if (pairs) 2 else 1;
}
pub fn emitCpuMetadata(cpu: anytype, logical: usize, pairs: bool, sink: anytype) !void {
    if (cpu.log_size > 22) return error.UnqualifiedWideClockGkr;
    if (cpu.u8_pairs != pairs) return error.LocalGkrMetadataShape;
    const main = try cpu.row(logical);
    const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.zero(), M.zero() };
    const Adapter = struct {
        target: @TypeOf(sink),
        pub fn emit(self: *@This(), relation: Fns.Relation, tuple: anytype, weight: M) void {
            self.target.emitBase(relation, tuple, weight);
        }
    };
    var adapter = Adapter{ .target = sink };
    Fns.cpuModeFor(M, &fixed, &main, M.fromCanonical(cpu.epoch), pairs, &adapter);
}
pub fn emitAndMetadata(logical: usize, and_count: u64, pair_counts: []const u32, pairs: bool, sink: anytype) !void {
    if (logical >= 65536 or and_count >= core.fields.m31.Modulus or pair_counts.len != (if (pairs) @as(usize, 65536) else 0)) return error.LocalGkrMetadataShape;
    const raw = A.providers.tables.Kind.byte_and.tupleAt(logical);
    const tuple = [3]M{ M.fromCanonical(raw[0]), M.fromCanonical(raw[1]), M.fromCanonical(raw[2]) };
    sink.emitBase(.and_, tuple, M.fromCanonical(@intCast(and_count)).neg());
    if (pairs) {
        const n = pair_counts[logical];
        if (n >= core.fields.m31.Modulus) return error.LocalGkrMultiplicityMass;
        sink.emitBase(.byte_pair, [4]M{ tuple[0], tuple[1], M.zero(), M.one() }, M.fromCanonical(n).neg());
    }
}
