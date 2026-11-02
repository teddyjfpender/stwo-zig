//! One typed partition of the bulk authority: OWNER/range stay proof-local;
//! RAM14 remains an authenticated global debt. No tuple or MAIN copy is stored.
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.crypto.bulk_memory;
const E = A.evaluation;
const Counts = struct { local: u32 = 0, ram: u32 = 0 };
pub fn emitLocalFor(comptime F: type, comptime kind: B.layout.Kind, fixed: []const F, main: []const F, sink: anytype) void {
    const Target = @TypeOf(sink);
    const Route = struct {
        target: Target,
        pub fn emit(self: *@This(), comptime relation: u2, tuple: anytype, weight: F) void {
            switch (relation) {
                B.equations.RAM => {},
                B.equations.OWNER => self.target.emit(.owner, tuple, weight),
                B.equations.RANGE16 => self.target.emit(.range16, tuple, weight),
                else => unreachable,
            }
        }
    };
    var route = Route{ .target = sink };
    B.equations.emitQueries(F, kind, fixed, main, &route);
}
pub fn emitGlobalFor(comptime F: type, comptime kind: B.layout.Kind, fixed: []const F, main: []const F, sink: anytype) void {
    const Target = @TypeOf(sink);
    const Route = struct {
        target: Target,
        pub fn emit(self: *@This(), comptime relation: u2, tuple: anytype, weight: F) void {
            if (relation == B.equations.RAM) self.target.emit(.ram, tuple, weight);
        }
    };
    var route = Route{ .target = sink };
    B.equations.emitQueries(F, kind, fixed, main, &route);
}
fn counts(comptime kind: B.layout.Kind) Counts {
    const M = @import("stwo_core").fields.m31.M31;
    const Counter = struct {
        result: Counts = .{},
        pub fn emit(self: *@This(), comptime relation: u2, _: anytype, _: M) void {
            if (relation == B.equations.RAM) self.result.ram += 1 else self.result.local += 1;
        }
    };
    var counter = Counter{};
    B.equations.emitQueries(M, kind, &([_]M{M.zero()} ** B.layout.fixedWidth(kind)), &([_]M{M.zero()} ** B.layout.main(kind)), &counter);
    return counter.result;
}
pub const COUNTS = blk: {
    @setEvalBranchQuota(1000000);
    var out: [@typeInfo(B.layout.Kind).@"enum".fields.len]Counts = undefined;
    for (@import("std").enums.values(B.layout.Kind), &out) |kind, *entry| entry.* = counts(kind);
    break :blk out;
};
pub fn localTerms(kind: B.layout.Kind) u32 {
    return COUNTS[@intFromEnum(kind)].local;
}
pub fn ramTerms(kind: B.layout.Kind) u32 {
    return COUNTS[@intFromEnum(kind)].ram;
}
