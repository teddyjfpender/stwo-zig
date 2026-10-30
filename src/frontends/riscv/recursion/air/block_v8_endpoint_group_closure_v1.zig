//! Symbolic Group closure over the SAME authenticated physical claim ports.
//! CPU/register/local RAM vanish MEMBER BY MEMBER. Only positive provider
//! demand aggregates; a residual cannot cancel a different cohort's residual.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const A = @import("block_v8_window_closure_algebra_v1.zig");
const Profile = @import("../block_v8_endpoint_group_profile_v1.zig");
pub const WORDS_PER_MEMBER: usize = 104;
fn words(a: std.mem.Allocator, p: *const Profile.Owned) ![]u32 {
    const result = try a.alloc(u32, try std.math.mul(usize, WORDS_PER_MEMBER, p.layout.n));
    errdefer a.free(result);
    for (p.statement.input.members, 0..) |member, index| {
        const data = member.shape.public_data;
        const completion = data.completion orelse return error.MissingCompletion;
        if (completion.kind != .unretired_program_fetch and completion.kind != .unretired_self_loop) return error.UnsupportedGroupCompletion;
        const out = result[index * WORDS_PER_MEMBER ..][0..WORDS_PER_MEMBER];
        out[0] = data.initial_pc;
        out[1] = data.final_pc;
        out[2] = data.clock;
        @memcpy(out[3..35], &data.initial_regs);
        @memcpy(out[35..67], &data.final_regs);
        @memcpy(out[67..99], &data.reg_last_clock);
        out[99] = completion.address;
        const decoded = try @import("../../air/program/decode.zig").decodeProgramWordForProfile(p.statement.trusted.profile, completion.value);
        @memcpy(out[100..104], &decoded);
    }
    return result;
}
pub fn appendPublic(a: std.mem.Allocator, p: *const Profile.Owned, output: *std.ArrayList(Q)) !void {
    const data = try words(a, p);
    defer a.free(data);
    for (data) |value| for (0..4) |byte| try output.append(a, Q.fromBase(M.fromCanonical((value >> @as(u5, @intCast(8 * byte))) & 255)));
}
fn word(bytes: [4]S) S {
    var result = S.zero();
    for (bytes, 0..) |value, i| result = result.add(value.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * i))))));
    return result;
}
pub fn record(_: std.mem.Allocator, builder: *G.Builder, p: *const Profile.Owned, ports: []const S, bytes: []const S, draws: [53][2]S) !void {
    if (bytes.len != try std.math.mul(usize, p.layout.n, 4 * WORDS_PER_MEMBER)) return error.InvalidGroupClosurePublicFrame;
    const universal = try G.ChallengeSet.init(draws[0..47].*);
    const state = universal.get(.registers_state);
    const memory = universal.get(.memory_access);
    const program = universal.get(.program_access);
    var at: usize = 0;
    var ranges = S.zero();
    var program_sum = S.zero();
    var fetches = S.zero();
    var byte_requests = S.zero();
    var tables: [6]S = @splat(S.zero());
    for (p.context.members, p.statement.input.members, 0..) |member, input, index| {
        const raw = bytes[index * 4 * WORDS_PER_MEMBER ..][0 .. 4 * WORDS_PER_MEMBER];
        var words_s: [WORDS_PER_MEMBER][4]S = undefined;
        for (&words_s, 0..) |*value, i| value.* = raw[4 * i ..][0..4].*;
        var boundary = A.Boundary(S){ .initial_pc = word(words_s[0]), .final_pc = word(words_s[1]), .final_clock_plus_one = word(words_s[2]).add(S.one()), .initial_register_bytes = undefined, .final_register_bytes = undefined, .register_last_clock = undefined };
        for (0..32) |reg| {
            boundary.initial_register_bytes[reg] = words_s[3 + reg];
            boundary.final_register_bytes[reg] = words_s[35 + reg];
            boundary.register_last_clock[reg] = word(words_s[67 + reg]);
        }
        try builder.constrainZero(word(words_s[99]).sub(boundary.final_pc));
        const slots = member.native.?.layout.slots;
        if (at > ports.len or 8 + slots.len + 11 > ports.len - at) return error.InvalidGroupClosurePhysicalFrame;
        const native_ports = ports[at + 8 ..][0..slots.len];
        const native = try A.native(S, slots, native_ports, boundary, .{ .z = state.z, .powers = state.alpha_powers[0..2].* }, .{ .z = memory.z, .powers = memory.alpha_powers[0..7].* });
        at += 8 + slots.len;
        const endpoint = ports[at..][0..11];
        at += 11;
        // Independent residual checks precede all provider aggregation.
        try builder.constrainZero(native.state);
        try builder.constrainZero(native.registers);
        try builder.constrainZero(native.ordinary_memory.add(native.clock_memory).add(endpoint[0]));
        for (endpoint[2..9]) |sum| ranges = ranges.add(sum);
        byte_requests = byte_requests.add(endpoint[9]).add(endpoint[10]);
        for (&tables, native.tables) |*sum, term| sum.* = sum.add(term);
        var tuple: [5]S = undefined;
        for (&tuple, 0..) |*value, i| value.* = word(words_s[99 + i]);
        program_sum = program_sum.sub((try program.combine(&tuple)).inverse());
        fetches = fetches.add(S.one());
        for (slots, native_ports) |slot, claim| if (slot.kind == .program) {
            program_sum = program_sum.add(claim);
            fetches = fetches.add(S.fromBase(M.fromCanonical(slot.n_rows)));
        };
        if (input.endpoint_count >= (core.fields.m31.Modulus - 1) / 13) return error.UnboundedGroupClosureCounts;
    }
    // Public metadata admission also checks this chain. Reproduce its CPU
    // equalities algebraically so the consolidated verifier circuit itself
    // connects every member's committed execution boundary.
    for (0..p.layout.n - 1) |i| {
        const prior = bytes[i * 4 * WORDS_PER_MEMBER ..][0 .. 4 * WORDS_PER_MEMBER];
        const next = bytes[(i + 1) * 4 * WORDS_PER_MEMBER ..][0 .. 4 * WORDS_PER_MEMBER];
        for (0..4) |byte| try builder.constrainZero(prior[4 + byte].sub(next[byte]));
        for (0..32) |reg| for (0..4) |byte| try builder.constrainZero(prior[4 * (35 + reg) + byte].sub(next[4 * (3 + reg) + byte]));
    }
    if (at > ports.len or ports.len - at != 9) return error.InvalidGroupClosurePhysicalFrame;
    try builder.constrainZero(ranges.add(ports[at]));
    try builder.constrainZero(ports[at + 1].sub(S.fromBase(M.fromCanonical(try std.math.mul(u32, p.scope.endpoint_count_total, 13)))));
    try builder.constrainZero(program_sum.add(ports[at + 2]));
    const table_providers = ports[at + 3 ..][0..6];
    for (tables, table_providers, 0..) |request, provider, i| {
        var sum = request.add(provider);
        if (i == @intFromEnum(@import("../../air/lookups/tables/schema.zig").Kind.range_check_8_8)) sum = sum.add(byte_requests);
        try builder.constrainZero(sum);
    }
    try builder.constrainZero(fetches.sub(S.fromBase(M.fromCanonical(@intCast(p.statement.input.program_plan.expected_fetches)))));
    // Endpoint plane1 remains authenticated and OPEN. The same-root late
    // bridge and global provider must close it in a separate recursive join.
}
