//! Immutable local ELF/ROM admission, without constructing any RW memory
//! initialization interval table. The complete global memory policy belongs
//! to the later shared provider. This owner is not proof authority.
const std = @import("std");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Loader = @import("../runner/elf_loader.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const Owned = struct {
    a: std.mem.Allocator,
    elf_sha256: [32]u8,
    info: Loader.ElfInfo,
    leaves: []Tree.Leaf,
    root: Tree.Digest,
    pub fn init(a: std.mem.Allocator, elf: []const u8, expected: [32]u8, profile: Loader.ExecutionProfile, limits: Initial.Limits) !Owned {
        if (elf.len > limits.max_elf_bytes or !std.meta.eql(@import("block_v5_initial_sources_v1.zig").sha256(elf), expected)) return error.UntrustedEndpointLocalElf;
        try Loader.validateReleaseAbiForProfile(elf, profile);
        const addresses = try Initial.loadAddresses(a, elf, limits);
        defer a.free(addresses);
        var memory = try @import("../runner/memory.zig").Memory.initFallible(a);
        defer memory.deinit();
        // All infallible loader writes have prepared bounded backing pages.
        try memory.prepareAlignedWordWrites(addresses);
        const info = try Loader.loadElfForProfile(elf, &memory, profile);
        try @import("block_v5_initial_sources_v1.zig").validateLayout(info.memory_layout);
        const lower = info.memory_layout.program_base;
        const upper = info.memory_layout.program_end;
        if (lower & 3 != 0 or upper & 3 != 0 or upper <= lower or (upper - lower) / 4 > limits.max_initialized_words) return error.InvalidEndpointLocalRomGeometry;
        const leaves = try a.alloc(Tree.Leaf, upper - lower);
        errdefer a.free(leaves);
        for (0..(upper - lower) / 4) |i| {
            const address = lower + 4 * @as(u32, @intCast(i));
            const decoded = try @import("../air/program/decode.zig").decodeDeclaredProgramWordForProfile(profile, memory.readU32(address));
            for (decoded, 0..) |value, j| leaves[4 * i + j] = .{ .index = address + @as(u32, @intCast(j)), .value = value };
        }
        return .{ .a = a, .elf_sha256 = expected, .info = info, .leaves = leaves, .root = try @import("../air/program/blake3_root_cache.zig").computeRoot(leaves) };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.leaves);
        self.* = undefined;
    }
};
