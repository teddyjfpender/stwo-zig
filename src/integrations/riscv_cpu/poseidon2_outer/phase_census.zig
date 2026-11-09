//! Source topology counters. Observation only: never emits circuit operations.
const Context = @import("context.zig").Context;
pub const Counts = struct {
    eq: u64 = 0,
    arithmetic: u64 = 0,
    m31_to_u32: u64 = 0,
    poseidon: u64 = 0,
    variables: u64 = 0,
    guessed_variables: u64 = 0,
    pub fn take(ctx: *const Context) @This() {
        const g = ctx.base.gate_counts;
        return .{ .eq = g.eq, .arithmetic = g.qm31_ops, .m31_to_u32 = g.m31_to_u32, .poseidon = ctx.calls.items.len, .variables = ctx.base.circuit.n_vars, .guessed_variables = ctx.base.stats.guess };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        var out: @This() = .{};
        inline for (@import("std").meta.fields(@This())) |field| @field(out, field.name) = @field(a, field.name) - @field(b, field.name);
        return out;
    }
    pub fn add(a: @This(), b: @This()) @This() {
        var out: @This() = .{};
        inline for (@import("std").meta.fields(@This())) |field| @field(out, field.name) = @field(a, field.name) + @field(b, field.name);
        return out;
    }
};
pub const Parts = struct {
    public_scope: Counts = .{},
    local_gkr: Counts = .{},
    claims_shared: Counts = .{},
    source_publics: Counts = .{},
    cpu_oods: Counts = .{},
    pcs_oods_and_transcript: Counts = .{},
    pcs_sampled_mix_and_queries: Counts = .{},
    pcs_merkle: Counts = .{},
    deep: Counts = .{},
    fri: Counts = .{},
};
