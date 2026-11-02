//! Typed partition of the original sponge tuple authority. No local/global
//! tuple is reimplemented, omitted for zero weights, or reconstructed from LDE.
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak_sponge;
const E = A.evaluation;
const Counts = struct { local: u32 = 0, ram: u32 = 0, kio: u32 = 0 };
pub fn emitLocalFor(comptime F: type, comptime kind: K.layout.Kind, fixed: []const F, main: []const F, first_id: u32, sink: anytype) void {
    const Target = @TypeOf(sink);
    const Route = struct {
        target: Target,
        pub fn emit(self: *@This(), comptime relation: u3, tuple: anytype, weight: F) void {
            switch (relation) {
                K.equations.RAM, K.equations.IO => {},
                K.equations.OWNER => self.target.emit(.owner, tuple, weight),
                K.equations.AND => self.target.emit(.and_, tuple, weight),
                K.equations.RANGE16 => self.target.emit(.range16, tuple, weight),
                K.equations.RANGE8 => self.target.emit(.range8, tuple, weight),
                else => unreachable,
            }
        }
    };
    var route = Route{ .target = sink };
    K.equations.emitRawFor(F, kind, fixed, main, first_id, &route);
}
pub fn emitGlobalFor(comptime F: type, comptime kind: K.layout.Kind, fixed: []const F, main: []const F, first_id: u32, sink: anytype) void {
    const Target = @TypeOf(sink);
    const Route = struct {
        target: Target,
        pub fn emit(self: *@This(), comptime relation: u3, tuple: anytype, weight: F) void {
            switch (relation) {
                K.equations.RAM => self.target.emit(.ram, tuple, weight),
                K.equations.IO => self.target.emit(.kio, tuple, weight),
                else => {},
            }
        }
    };
    var route = Route{ .target = sink };
    K.equations.emitRawFor(F, kind, fixed, main, first_id, &route);
}
fn counts(comptime kind: K.layout.Kind) Counts {
    const M = @import("stwo_core").fields.m31.M31;
    const Counter = struct {
        result: Counts = .{},
        pub fn emit(self: *@This(), comptime relation: u3, _: anytype, _: M) void {
            switch (relation) {
                K.equations.RAM => self.result.ram += 1,
                K.equations.IO => self.result.kio += 1,
                else => self.result.local += 1,
            }
        }
    };
    var counter = Counter{};
    K.equations.emitRawFor(M, kind, &([_]M{M.zero()} ** K.layout.FIXED), &([_]M{M.zero()} ** K.layout.main(kind)), 1, &counter);
    return counter.result;
}
pub const COUNTS = blk: {
    @setEvalBranchQuota(1000000);
    break :blk [2]Counts{ counts(.call), counts(.perm) };
};
pub fn localTerms(kind: K.layout.Kind) u32 {
    return COUNTS[@intFromEnum(kind)].local;
}
pub fn ramTerms(kind: K.layout.Kind) u32 {
    return COUNTS[@intFromEnum(kind)].ram;
}
pub fn kioTerms(kind: K.layout.Kind) u32 {
    return COUNTS[@intFromEnum(kind)].kio;
}
pub fn globalWidth(kind: K.layout.Kind) usize {
    return 8 * ((ramTerms(kind) + 1) / 2 + 1 + (kioTerms(kind) + 1) / 2 + 1);
}
pub fn globalConstraints(kind: K.layout.Kind) usize {
    return (ramTerms(kind) + 1) / 2 + 2 + (kioTerms(kind) + 1) / 2 + 2;
}
/// Exact pure RAM/KIO debts under independently derived shared challenges.
/// Both denominator tuples and weights come from emitRawFor above.
pub fn emitGlobalConstraintsFor(comptime F: type, comptime kind: K.layout.Kind, fixed: []const F, main: []const F, first_id: u32, shared: anytype, claims: anytype, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    const Sec = E.SecureFor(F);
    const Route = struct {
        shared: @TypeOf(shared),
        ram_d: [ramTerms(kind)]Sec = undefined,
        ram_w: [ramTerms(kind)]F = undefined,
        kio_d: [kioTerms(kind)]Sec = undefined,
        kio_w: [kioTerms(kind)]F = undefined,
        r: usize = 0,
        k: usize = 0,
        pub fn emit(self: *@This(), comptime relation: u3, tuple: anytype, weight: F) void {
            switch (relation) {
                K.equations.RAM => {
                    self.ram_d[self.r] = E.denominatorFor(F, self.shared.ram.offset, &self.shared.ram.coefficients, &tuple, true);
                    self.ram_w[self.r] = weight;
                    self.r += 1;
                },
                K.equations.IO => {
                    self.kio_d[self.k] = E.denominatorFor(F, self.shared.kio.offset, &self.shared.kio.coefficients, &tuple, true);
                    self.kio_w[self.k] = weight;
                    self.k += 1;
                },
                else => {},
            }
        }
    };
    var route = Route{ .shared = shared };
    K.equations.emitRawFor(F, kind, fixed, main, first_id, &route);
    const rw = 8 * ((ramTerms(kind) + 1) / 2 + 1);
    if (current.len != globalWidth(kind) or previous.len != current.len) return error.InvalidWideGlobalInteractionShape;
    try A.main_only.global_classic.linearPairsFor(F, &route.ram_d, &route.ram_w, current[0..rw], previous[0..rw], fixed[1], fixed[2], claims.ram, sink);
    try A.main_only.global_classic.linearPairsFor(F, &route.kio_d, &route.kio_w, current[rw..], previous[rw..], fixed[1], fixed[2], claims.kio, sink);
}
