//! Same typed native-parent AIR authority as V5, with the exact Join public
//! supply coordinates specialized by the independently reconstructed child key.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("../block_v8_window_root_profile_v1.zig");
const Shared = @import("block_v5_open_parent_composition_v2.zig");
pub const Compiled = Shared.Compiled;
pub fn compile(a: std.mem.Allocator, p: *const Profile.Owned) !Compiled {
    try p.validate();
    return Shared.compileShape(a, &p.admission);
}
pub fn prepare(a: std.mem.Allocator, p: *const Profile.Owned, c: *const Profile.Capture) !@import("blake3_execution_composition.zig").Prepared {
    try p.requireCapture(c);
    return Shared.prepare(a, &p.admission, c.parent);
}
pub const SPAN_WORDS = 110;
pub fn publicValues(a: std.mem.Allocator, p: *const Profile.Owned) ![]core.fields.qm31.QM31 {
    try p.validate();
    return spanValues(a, p.span);
}
pub fn spanValues(a: std.mem.Allocator, span: @import("../block_v8_window_root_statement_v1.zig").WindowSpan) ![]core.fields.qm31.QM31 {
    try span.validate();
    const out = try a.alloc(core.fields.qm31.QM31, SPAN_WORDS);
    const Q = core.fields.qm31.QM31;
    const M = core.fields.m31.M31;
    @memset(out, Q.zero());
    out[0] = Q.fromBase(M.fromCanonical(@intCast(span.first_cycle)));
    out[1] = Q.fromBase(M.fromCanonical(@intCast(span.cycles)));
    putDigest(out[2..10], span.elf_sha256);
    putDigest(out[10..18], span.incoming_snapshot_id);
    putDigest(out[18..26], span.outgoing_snapshot_id);
    out[26] = packWord(span.initial_cpu.pc);
    out[59] = packWord(span.final_cpu.pc);
    for (span.initial_cpu.regs, span.final_cpu.regs, 0..) |x, y, i| {
        out[27 + i] = packWord(x);
        out[60 + i] = packWord(y);
    }
    if (span.initial_policy_id) |id| {
        out[92] = Q.one();
        putDigest(out[93..101], id);
    }
    if (span.terminal_policy_id) |id| {
        out[101] = Q.one();
        putDigest(out[102..110], id);
    }
    return out;
}
fn putDigest(out: []core.fields.qm31.QM31, bytes: [32]u8) void {
    for (out, 0..) |*v, i| v.* = packWord(std.mem.readInt(u32, bytes[4 * i ..][0..4], .little));
}
fn packWord(word: u32) core.fields.qm31.QM31 {
    var bytes: [4]core.fields.m31.M31 = undefined;
    for (&bytes, 0..) |*b, i| b.* = core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
    return core.fields.qm31.QM31.fromM31Array(bytes);
}
