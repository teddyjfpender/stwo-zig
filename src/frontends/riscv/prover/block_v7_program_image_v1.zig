//! Complete decoded ELF ROM, independently rebuilt before v7 admission.
const std = @import("std");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const Owned = struct {
    a: std.mem.Allocator,
    leaves: []Tree.Leaf,
    root: Tree.Digest,
    pub fn init(a: std.mem.Allocator, elf: []const u8, policy: *const Initial.Owned, limits: Initial.Limits) !Owned {
        if (elf.len > limits.max_elf_bytes or !std.meta.eql(@import("block_v5_initial_sources_v1.zig").sha256(elf), policy.elf_sha256)) return error.UntrustedV7Elf;
        const addresses = try Initial.loadAddresses(a, elf, limits);
        defer a.free(addresses);
        var memory = try @import("../runner/memory.zig").Memory.initFallible(a);
        defer memory.deinit();
        try memory.prepareAlignedWordWrites(addresses);
        const info = try @import("../runner/elf_loader.zig").loadElfForProfile(elf, &memory, policy.info.execution_profile);
        if (!std.meta.eql(info, policy.info)) return error.UntrustedV7ProgramImage;
        const lower = info.memory_layout.program_base;
        const upper = info.memory_layout.program_end;
        if (lower & 3 != 0 or upper & 3 != 0 or upper <= lower or (upper - lower) / 4 > limits.max_initialized_words) return error.InvalidV7ProgramGeometry;
        const leaves = try a.alloc(Tree.Leaf, upper - lower);
        errdefer a.free(leaves);
        for (0..(upper - lower) / 4) |i| {
            const address = lower + 4 * @as(u32, @intCast(i));
            const decoded = try @import("../air/program/decode.zig").decodeDeclaredProgramWordForProfile(info.execution_profile, memory.readU32(address));
            for (decoded, 0..) |value, j| leaves[4 * i + j] = .{ .index = address + @as(u32, @intCast(j)), .value = value };
        }
        return .{ .a = a, .leaves = leaves, .root = try @import("../air/program/blake3_root_cache.zig").computeRoot(leaves) };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.leaves);
        self.* = undefined;
    }
};
