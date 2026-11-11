//! Opt-in R7 source lowering for complete DEEP numerator dots. The graph owner
//! records all inputs and unique producers; callbacks cannot publish free debt.
const C = @import("../context.zig");
const Common = @import("../../rv64_recursion/om31_native/common.zig");
const Dot = @import("../../rv64_recursion/om31_native/deep_dot.zig");
const Source = @import("authority.zig");
threadlocal var active: ?*C.Context = null;
fn emit(algebra: *Common.Context, weights: []const Common.F, scalars: []const Common.Var) !Common.F {
    const owner = active orelse return error.NativeDotScopeRequired;
    if (owner.algebra() != algebra or weights.len != scalars.len) return error.NativeDotScopeMismatch;
    const terms = try algebra.scratch().alloc(Source.Term, weights.len);
    for (terms, weights, scalars) |*term, weight, scalar| term.* = .{ .weight = .{ weight.c0.v.idx, weight.c1.v.idx }, .scalar = scalar.idx };
    const output = try owner.nativeDot(terms);
    return Common.F.wire(output[0], output[1]);
}
pub const Scope = struct {
    previous: ?*C.Context,
    hook: Dot.Scope,
    pub fn begin(owner: *C.Context) Scope {
        const previous = active;
        active = owner;
        return .{ .previous = previous, .hook = Dot.Scope.init(emit) };
    }
    pub fn deinit(self: *Scope) void {
        self.hook.deinit();
        active = self.previous;
    }
};
