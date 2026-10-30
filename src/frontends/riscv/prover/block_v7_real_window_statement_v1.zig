//! Explicit bounded machine-state transition admission for the existing
//! SHA-capable canonical original leaf. This is not the terminal v7 execution
//! statement and does not prove the skipped Ethereum prefix or block validity.
//! Both complete RW endpoint states are independently selected benchmark input.
const std = @import("std");
const C = @import("block_v7_real_window_capture_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Public = @import("../air/public_data.zig");
const Memory = @import("../runner/memory.zig").Memory;
pub const Trusted = struct {
    elf_sha256: C.Digest,
    incoming_sha256: C.Digest,
    outgoing_sha256: C.Digest,
    window: C.Window,
};
pub const Statement = struct {
    trusted: Trusted,
    initial_cpu: @import("../runner/cpu.zig").Cpu,
    final_cpu: @import("../runner/cpu.zig").Cpu,
    roots: [3]Tree.Digest,
    completion: Public.Completion,
    input_start: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    pub fn derive(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, limits: Initial.Limits) !Statement {
        // Non-first, unfinished windows have no public input/output exclusions
        // in the original memory projection. Fresh prefixes need a distinct
        // public-I/O projection and are deliberately rejected here.
        if (trusted.window.skip_cycles == 0 or trusted.window.cycles == 0 or
            trusted.window.cycles > 1 << 18 or !std.meta.eql(incoming.identity(), trusted.incoming_sha256) or
            !std.meta.eql(outgoing.identity(), trusted.outgoing_sha256)) return error.UntrustedRealWindowState;
        _ = try std.math.add(u64, trusted.window.skip_cycles, trusted.window.cycles);
        var initial = try Initial.Owned.derive(a, elf, trusted.elf_sha256, .rv32im_zkvm_ethereum_sha_v1, limits);
        defer initial.deinit();
        var image = try Image.Owned.init(a, elf, &initial, limits);
        defer image.deinit();
        const addresses = try Initial.loadAddresses(a, elf, limits);
        defer a.free(addresses);
        var memory = try Memory.initFallible(a);
        defer memory.deinit();
        try memory.prepareAlignedWordWrites(addresses);
        _ = try @import("../runner/elf_loader.zig").loadElfForProfile(elf, &memory, .rv32im_zkvm_ethereum_sha_v1);
        const layout = initial.info.memory_layout;
        if (!layout.isProgramAddr(incoming.cpu.pc) or !layout.isProgramAddr(outgoing.cpu.pc) or
            (incoming.cpu.pc | outgoing.cpu.pc) & 3 != 0) return error.UntrustedRealWindowState;
        return .{
            .trusted = trusted,
            .initial_cpu = incoming.cpu,
            .final_cpu = outgoing.cpu,
            .roots = .{ image.root, try memoryRoot(a, incoming, &memory, layout, addresses, limits.max_initialized_words), try memoryRoot(a, outgoing, &memory, layout, addresses, limits.max_initialized_words) },
            .completion = Public.Completion.unretiredProgramFetch(outgoing.cpu.pc, memory.readU32(outgoing.cpu.pc)),
            .input_start = initial.info.input_start,
            .output_len_addr = initial.info.output_len,
            .output_data_addr = initial.info.output_data,
        };
    }
    pub fn admit(self: Statement, data: Public.Blake3PublicData) !void {
        try data.validate();
        if (data.clock != self.trusted.window.cycles or data.initial_pc != self.initial_cpu.pc or data.final_pc != self.final_cpu.pc or
            !std.meta.eql(data.initial_regs, self.initial_cpu.regs) or !std.meta.eql(data.final_regs, self.final_cpu.regs) or
            !std.meta.eql(data.program_root orelse return error.UntrustedRealWindowStatement, self.roots[0]) or
            !std.meta.eql(data.initial_rw_root orelse return error.UntrustedRealWindowStatement, self.roots[1]) or
            !std.meta.eql(data.final_rw_root orelse return error.UntrustedRealWindowStatement, self.roots[2]) or
            !std.meta.eql(data.completion orelse return error.UntrustedRealWindowStatement, self.completion)) return error.UntrustedRealWindowStatement;
        const io = data.io_entries;
        if (io.input_len != 0 or io.input_words.len != 0 or io.output_len != 0 or io.output_words.len != 0 or
            io.input_start != self.input_start or io.output_len_addr != self.output_len_addr or io.output_data_addr != self.output_data_addr)
            return error.UntrustedRealWindowStatement;
    }
    /// Two independent full roots do not prove untouched cells stayed equal.
    /// Every changed RW word must have BOTH original boundary providers, with
    /// a nonzero final access clock. Their native LogUp closure then requires
    /// an actual access chain; the remaining complete endpoint cells are equal.
    pub fn admitPlan(self: Statement, incoming: C.Snapshot, outgoing: C.Snapshot, plan: *const @import("blake3_commitment_plan.zig").Plan) !void {
        try plan.validate();
        if (!std.meta.eql(plan.roots, self.roots) or !std.meta.eql(incoming.identity(), self.trusted.incoming_sha256) or
            !std.meta.eql(outgoing.identity(), self.trusted.outgoing_sha256)) return error.UntrustedRealWindowStatement;
        var left: usize = 0;
        var right: usize = 0;
        while (left < incoming.words.len or right < outgoing.words.len) {
            const address = @min(if (left < incoming.words.len) incoming.words[left].address else std.math.maxInt(u32), if (right < outgoing.words.len) outgoing.words[right].address else std.math.maxInt(u32));
            const initial_value = if (left < incoming.words.len and incoming.words[left].address == address) incoming.words[left].value else 0;
            const final_value = if (right < outgoing.words.len and outgoing.words[right].address == address) outgoing.words[right].value else 0;
            if (left < incoming.words.len and incoming.words[left].address == address) left += 1;
            if (right < outgoing.words.len and outgoing.words[right].address == address) right += 1;
            if (initial_value == final_value) continue;
            const first = boundaryClock(plan, address, false) orelse return error.UnprovedRealWindowStateChange;
            const last = boundaryClock(plan, address, true) orelse return error.UnprovedRealWindowStateChange;
            if (first != 0 or last == 0) return error.UnprovedRealWindowStateChange;
        }
    }
};
fn boundaryClock(plan: *const @import("blake3_commitment_plan.zig").Plan, address: u32, final: bool) ?u32 {
    var lower: usize = 0;
    var upper = plan.memories.len;
    while (lower < upper) {
        const middle = lower + (upper - lower) / 2;
        const item = plan.memories[middle];
        const item_final = item.direction == .final;
        if ((item_final == final and item.address < address) or (!item_final and final)) lower = middle + 1 else upper = middle;
    }
    if (lower == plan.memories.len) return null;
    const item = plan.memories[lower];
    return if ((item.direction == .final) == final and item.address == address) item.clock else null;
}
fn memoryRoot(a: std.mem.Allocator, state: C.Snapshot, elf: *const Memory, layout: @import("../runner/memory_state.zig").MemoryLayout, loaded: []const u32, max_words: usize) !Tree.Digest {
    if (state.cpu.regs[0] != 0 or state.words.len > max_words) return error.UntrustedRealWindowState;
    var leaves: std.ArrayList(Tree.Leaf) = .empty;
    defer leaves.deinit(a);
    for (state.words, 0..) |word, i| {
        if (word.address & 3 != 0 or (i != 0 and state.words[i - 1].address >= word.address)) return error.UntrustedRealWindowState;
        if (layout.isProgramAddr(word.address)) {
            if (elf.readU32(word.address) != word.value) return error.UntrustedRealWindowProgram;
        } else if (layout.isRwAddr(word.address)) {
            if (word.value != 0) try leaves.append(a, .{ .index = try Tree.memoryIndex(word.address), .value = word.value });
        } else {
            // Real ELF PT_LOAD records may include the ELF header before
            // __text_start. Only actual independently loaded words qualify;
            // Memory.readU32's implicit zero is not an authority for arbitrary
            // out-of-layout addresses. These immutable words must match in
            // both independently selected endpoint snapshots.
            var lower: usize = 0;
            var upper = loaded.len;
            while (lower < upper) {
                const middle = lower + (upper - lower) / 2;
                if (loaded[middle] < word.address) lower = middle + 1 else upper = middle;
            }
            if (lower == loaded.len or loaded[lower] != word.address or elf.readU32(word.address) != word.value)
                return error.UntrustedRealWindowState;
        }
    }
    return Tree.TreeHasher.init(.memory).root(leaves.items);
}

test "real window readonly ELF words require exact load membership and value" {
    const a = std.testing.allocator;
    var memory = try Memory.initFallible(a);
    defer memory.deinit();
    try memory.prepareAlignedWordWrites(&.{0});
    memory.writeU32AssumePrepared(0, 0x464c457f);
    var words = [_]C.Word{.{ .address = 0, .value = 0x464c457f }};
    const snapshot: C.Snapshot = .{ .cpu = @import("../runner/cpu.zig").Cpu.init(0x400, 0), .words = &words };
    const layout = std.mem.zeroes(@import("../runner/memory_state.zig").MemoryLayout);
    _ = try memoryRoot(a, snapshot, &memory, layout, &.{0}, 10);
    words[0].value ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowState, memoryRoot(a, snapshot, &memory, layout, &.{0}, 10));
    words[0] = .{ .address = 4, .value = 0 };
    try std.testing.expectError(error.UntrustedRealWindowState, memoryRoot(a, snapshot, &memory, layout, &.{0}, 10));
}
