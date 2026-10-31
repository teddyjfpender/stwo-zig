//! Versioned job identity and LE section geometry. These hashes are corruption
//! and dispatch identities, never substitutes for a physical execution proof.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const Full = @import("rv64_full.zig");
const rv = @import("stwo_riscv_frontend").rv64_air;
pub const Digest = [32]u8;
pub const BYTES = 384;
pub const MAGIC = "RV64WP01";
pub const Identity = struct { request: Digest, program: Digest, input: Digest, terminal: Digest, policy: Digest, immutable_program_key: Digest };
pub const Metadata = struct { identity: Identity, index: u32, first_step: u64, before: rv.memory.values.Digest, after: rv.memory.values.Digest, geometry: rv.memory.values.Geometry = .chunk512 };
pub const Expected = struct { identity: Identity, authority: *const Full.ProgramAuthority, policy: *const rv.memory.policy.Policy, state_policy: rv.state_policy.Policy };
pub const Limits = struct { bytes: usize = 512 * 1024 * 1024, allocation_bytes: usize = 512 * 1024 * 1024, cells: u32 = 1 << 24, chunks: u32 = 1 << 19, steps: u32 = (1 << 22) - 1 };
pub const Header = struct {
    metadata: Metadata,
    cells: u32,
    chunks: u32,
    graph_bytes: usize,
    tape_bytes: usize,
    content_digest: Digest = @splat(0),
    pub fn bodyBytes(self: Header) !usize {
        var n: usize = 768;
        n = try std.math.add(usize, n, try std.math.mul(usize, self.cells, 32));
        n = try std.math.add(usize, n, try std.math.mul(usize, self.chunks, 8 + 64 * 21));
        return n;
    }
    pub fn totalBytes(self: Header) !usize {
        return std.math.add(usize, try std.math.add(usize, BYTES, try self.bodyBytes()), try std.math.add(usize, self.graph_bytes, self.tape_bytes));
    }
    pub fn validate(self: Header, limits: Limits) !void {
        if (limits.bytes > 512 * 1024 * 1024 or limits.allocation_bytes > 512 * 1024 * 1024 or self.metadata.geometry != .chunk512 or self.cells > limits.cells or self.chunks > limits.chunks or self.cells > @as(u64, self.chunks) * 64 or (self.cells == 0) != (self.chunks == 0) or (self.chunks == 0) != (self.graph_bytes == 0) or self.tape_bytes < 48 or try self.totalBytes() > limits.bytes) return error.WorkPacketResourceLimit;
        for ([_]rv.memory.values.Digest{ self.metadata.before, self.metadata.after }) |digest| for (digest) |limb| if (limb >= 0x7fff_ffff) return error.InvalidWorkPacketRoot;
        if (self.chunks == 0 and !std.mem.eql(u32, &self.metadata.before, &self.metadata.after)) return error.InvalidWorkPacketRoot;
    }
};
pub fn encode(h: Header) ![BYTES]u8 {
    var raw: [BYTES]u8 = @splat(0);
    @memcpy(raw[0..8], MAGIC);
    put(u32, raw[8..12], 1);
    put(u32, raw[12..16], @intFromBool(h.chunks != 0));
    put(u64, raw[16..24], try h.totalBytes());
    put(u32, raw[24..28], h.cells);
    put(u32, raw[28..32], h.chunks);
    put(u64, raw[32..40], h.graph_bytes);
    put(u64, raw[40..48], h.tape_bytes);
    put(u32, raw[48..52], h.metadata.index);
    put(u32, raw[52..56], 9);
    put(u64, raw[56..64], h.metadata.first_step);
    for (identityWords(h.metadata.identity), 0..) |digest, i| @memcpy(raw[64 + 32 * i ..][0..32], &digest);
    for (h.metadata.before, 0..) |limb, i| put(u32, raw[256 + 4 * i ..][0..4], limb);
    for (h.metadata.after, 0..) |limb, i| put(u32, raw[292 + 4 * i ..][0..4], limb);
    @memcpy(raw[328..360], &h.content_digest);
    return raw;
}
pub fn decode(raw: *const [BYTES]u8, file_bytes: u64, expected: Expected, limits: Limits) !Header {
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or get(u32, raw[8..12]) != 1 or get(u32, raw[12..16]) > 1 or get(u32, raw[52..56]) != 9 or !std.mem.allEqual(u8, raw[360..], 0)) return error.InvalidWorkPacketHeader;
    var ids: [6]Digest = undefined;
    for (&ids, 0..) |*digest, i| @memcpy(digest, raw[64 + 32 * i ..][0..32]);
    const identity = Identity{ .request = ids[0], .program = ids[1], .input = ids[2], .terminal = ids[3], .policy = ids[4], .immutable_program_key = ids[5] };
    if (!std.meta.eql(identity, expected.identity) or !std.mem.eql(u8, &identity.policy, &expected.policy.identity)) return error.WorkPacketIdentityMismatch;
    if (!std.mem.eql(u8, &identity.immutable_program_key, &programKey(expected.authority))) return error.WorkPacketAuthorityMismatch;
    var h = Header{ .metadata = .{ .identity = identity, .index = get(u32, raw[48..52]), .first_step = get(u64, raw[56..64]), .before = undefined, .after = undefined }, .cells = get(u32, raw[24..28]), .chunks = get(u32, raw[28..32]), .graph_bytes = std.math.cast(usize, get(u64, raw[32..40])) orelse return error.WorkPacketResourceLimit, .tape_bytes = std.math.cast(usize, get(u64, raw[40..48])) orelse return error.WorkPacketResourceLimit };
    for (&h.metadata.before, 0..) |*limb, i| limb.* = get(u32, raw[256 + 4 * i ..][0..4]);
    for (&h.metadata.after, 0..) |*limb, i| limb.* = get(u32, raw[292 + 4 * i ..][0..4]);
    @memcpy(&h.content_digest, raw[328..360]);
    try h.validate(limits);
    if ((get(u32, raw[12..16]) != 0) != (h.chunks != 0) or get(u64, raw[16..24]) != file_bytes or try h.totalBytes() != file_bytes) return error.InvalidWorkPacketSection;
    return h;
}
pub fn identityFor(config: Request.Config, authority: *const Full.ProgramAuthority, policy: *const rv.memory.policy.Policy) !Identity {
    var result: Identity = undefined;
    if (config.elf_sha256.len != 64 or config.input_sha256.len != 64 or config.expected_output.len != 86) return error.InvalidWorkPacketIdentity;
    _ = try std.fmt.hexToBytes(&result.program, config.elf_sha256);
    _ = try std.fmt.hexToBytes(&result.input, config.input_sha256);
    result.policy = policy.identity;
    result.immutable_program_key = programKey(authority);
    var terminal = std.crypto.hash.sha2.Sha256.init(.{});
    terminal.update("RV64-WORK-TERMINAL-V1");
    hash64(&terminal, config.terminal_pc);
    var output: [43]u8 = undefined;
    _ = try std.fmt.hexToBytes(&output, config.expected_output);
    terminal.update(&output);
    hash64(&terminal, config.symbols.halt_flag);
    hash64(&terminal, config.symbols.output_len);
    hash64(&terminal, config.symbols.output_data);
    result.terminal = terminal.finalResult();
    var request = std.crypto.hash.sha2.Sha256.init(.{});
    request.update("RV64-WORK-REQUEST-V1");
    for ([_]Digest{ result.program, result.input, result.terminal, result.policy, result.immutable_program_key }) |digest| request.update(&digest);
    const s = config.symbols;
    for ([_]u64{ s.input_start, s.input_end, s.halt_flag, s.output_len, s.output_data, s.output_end, s.stack_bottom, s.stack_top, s.heap_start, s.heap_end }) |value| hash64(&request, value);
    hash64(&request, config.batch_steps);
    hash64(&request, config.max_steps);
    hash64(&request, @intFromEnum(config.state_policy));
    hash64(&request, @intFromBool(config.omit_unused_arithmetic));
    result.request = request.finalResult();
    return result;
}
pub fn programKey(authority: *const Full.ProgramAuthority) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("RV64-WORK-PROGRAM-KEY-V1");
    hash.update(&authority.program.identity);
    hash64(&hash, @intFromEnum(authority.profile));
    hash64(&hash, @intFromEnum(authority.control_policy));
    return hash.finalResult();
}
fn identityWords(id: Identity) [6]Digest {
    return .{ id.request, id.program, id.input, id.terminal, id.policy, id.immutable_program_key };
}
fn hash64(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, .little);
    hash.update(&raw);
}
fn put(comptime T: type, bytes: *[@sizeOf(T)]u8, value: T) void {
    std.mem.writeInt(T, bytes, value, .little);
}
fn get(comptime T: type, bytes: *const [@sizeOf(T)]u8) T {
    return std.mem.readInt(T, bytes, .little);
}
