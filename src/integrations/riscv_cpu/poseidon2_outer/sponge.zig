//! Circuit twin of core.crypto.poseidon2_m31_sponge. Permutations use dedicated AIR.
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Var = B.Var;
pub const Hash = [9]Var;
pub const Domain = core.crypto.poseidon2_m31_sponge.Domain;
pub fn ForContext(comptime Context: type) type {
    return struct {
        context: *Context,
        state: [24]Var,
        at: usize = 0,
        const Self = @This();
        pub fn init(ctx: *Context, domain: Domain) !Self {
            const algebra = ctx.algebra();
            var state: [24]Var = @splat(algebra.zero());
            state[22] = algebra.one();
            state[23] = try algebra.constant(Q.fromBase(M.fromCanonical(@intFromEnum(domain))));
            return .{ .context = ctx, .state = state };
        }
        pub fn absorb(self: *Self, value: Var) !void {
            self.state[self.at] = try self.context.algebra().add(self.state[self.at], value);
            self.at += 1;
            if (self.at == 12) {
                self.state = try self.context.permute(self.state);
                self.at = 0;
            }
        }
        pub fn absorbMany(self: *Self, values: []const Var) !void {
            for (values) |value| try self.absorb(value);
        }
        pub fn absorbConstU32(self: *Self, word: u32) !void {
            const a = self.context.algebra();
            try self.absorb(try a.constant(Q.fromBase(M.fromCanonical(word & 0xffff))));
            try self.absorb(try a.constant(Q.fromBase(M.fromCanonical(word >> 16))));
        }
        pub fn absorbConstU64(self: *Self, word: u64) !void {
            try self.absorbConstU32(@truncate(word));
            try self.absorbConstU32(@truncate(word >> 32));
        }
        pub fn finish(self: Self) !Hash {
            var result = self;
            result.state[result.at] = try result.context.algebra().add(result.state[result.at], result.context.algebra().one());
            result.state = try result.context.permute(result.state);
            return result.state[0..9].*;
        }
    };
}
