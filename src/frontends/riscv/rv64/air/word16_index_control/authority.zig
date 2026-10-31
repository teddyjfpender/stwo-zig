//! Immutable address-ID and static-edge authority. IDs name unique full-u64
//! addresses, NEVER physical edge rows. Unsupported words remain nonfetchable.
//! This diagnostic admits ALU/binary only; it is not a full RV64 execution key.
const std = @import("std");
const core = @import("stwo_core");
const isa = @import("../../decode.zig");
const Program = @import("../program/setup.zig").Program;
const Ops = @import("../word16_v1/operations.zig");
const W = @import("../word16_cpu/public.zig");
const physical = @import("../word16_cpu/layout.zig").physical;
const M = core.fields.m31.M31;
pub const EXECUTION_FIELDS = 17;
pub const RAW_PC = EXECUTION_FIELDS;
pub const FIRST = RAW_PC + 4;
pub const LAST = FIRST + 1;
pub const FIXED = LAST + 1;
pub const NO_WORD = std.math.maxInt(u32);
pub const Decoded = isa.Instruction;
pub const Edge = struct { id: u32, next_id: u32, word: u32, taken: bool, executable: bool };
pub const Authority = struct {
    allocator: std.mem.Allocator,
    words: []u32,
    word_addresses: []u64,
    contiguous: bool = false,
    decoded: []Decoded,
    valid: []bool,
    admitted: []bool,
    word_rows: []u32,
    row_words: []u32,
    addresses: []u64,
    id_words: []u32,
    first_rows: []u32,
    edges: []Edge,
    fixed: []M,
    log_size: u32,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, expected: Program) !Authority {
        try expected.validate();
        const words = try a.dupe(u32, expected.words);
        errdefer a.free(words);
        const word_addresses = try a.alloc(u64, words.len);
        errdefer a.free(word_addresses);
        const decoded = try a.alloc(Decoded, words.len);
        errdefer a.free(decoded);
        const valid = try a.alloc(bool, words.len);
        errdefer a.free(valid);
        const admitted = try a.alloc(bool, words.len);
        errdefer a.free(admitted);
        var addresses: std.ArrayList(u64) = .empty;
        errdefer addresses.deinit(a);
        for (words, word_addresses, decoded, valid, admitted, 0..) |raw, *pc, *entry, *valid_entry, *admitted_entry, index| {
            pc.* = expected.pc(index);
            try addresses.append(a, pc.*);
            const instruction = isa.Instruction.decode(raw) catch {
                entry.* = .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0 };
                valid_entry.* = false;
                admitted_entry.* = false;
                continue;
            };
            const operation = Ops.classify(instruction.opcode);
            entry.* = instruction;
            valid_entry.* = true;
            admitted_entry.* = if (operation) |op| op.family == .alu or op.family == .binary else false;
            // Complete deterministic one-step STATIC superset. Dynamic JALR
            // destinations are not guessed from a request or execution path.
            try addresses.append(a, pc.* +% 4);
            if ((operation != null and operation.?.branch_predicate) or instruction.opcode == .JAL) {
                const target = pc.* +% @as(u64, @bitCast(instruction.imm));
                if (target & 3 == 0) try addresses.append(a, target);
            }
        }
        std.mem.sort(u64, addresses.items, {}, std.sort.asc(u64));
        var count: usize = 0;
        for (addresses.items) |pc| {
            if (count == 0 or addresses.items[count - 1] != pc) {
                addresses.items[count] = pc;
                count += 1;
            }
        }
        addresses.shrinkRetainingCapacity(count);
        if (count == 0 or count >= core.fields.m31.Modulus) return error.InvalidIndexAddressCardinality;
        const id_words = try a.alloc(u32, count);
        errdefer a.free(id_words);
        @memset(id_words, NO_WORD);
        const first_rows = try a.alloc(u32, count);
        errdefer a.free(first_rows);
        for (word_addresses, 0..) |pc, index| id_words[try find(addresses.items, pc)] = @intCast(index);
        var edges: std.ArrayList(Edge) = .empty;
        errdefer edges.deinit(a);
        for (addresses.items, id_words, first_rows, 0..) |pc, word, *first, id| {
            first.* = @intCast(edges.items.len);
            const executable = word != NO_WORD and admitted[word];
            const next_id = if (executable) try find(addresses.items, pc +% 4) else 0;
            try edges.append(a, .{ .id = @intCast(id), .next_id = next_id, .word = word, .taken = false, .executable = executable });
            if (executable and Ops.classify(decoded[word].opcode).?.branch_predicate) {
                const target = pc +% @as(u64, @bitCast(decoded[word].imm));
                if (target & 3 == 0) try edges.append(a, .{ .id = @intCast(id), .next_id = try find(addresses.items, target), .word = word, .taken = true, .executable = true });
            }
        }
        if (edges.items.len > 1 << 24) return error.InvalidIndexRomCardinality;
        const word_rows = try a.alloc(u32, words.len);
        errdefer a.free(word_rows);
        const row_words = try a.alloc(u32, edges.items.len);
        errdefer a.free(row_words);
        for (word_addresses, word_rows) |pc, *row| row.* = first_rows[try find(addresses.items, pc)];
        for (edges.items, row_words) |edge, *word| word.* = edge.word;
        const log_size: u32 = @intCast(@max(5, std.math.log2_int_ceil(usize, edges.items.len)));
        const n = @as(usize, 1) << @intCast(log_size);
        const fixed = try a.alloc(M, FIXED * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        // Padding is a TRUE address fact (id0, first full PC), even when the
        // first address is nonfetchable. It cannot invent id0->PC0 aliases.
        const padding_pc = W.word(M, addresses.items[0]);
        for (0..n) |row| for (padding_pc, 0..) |limb, c| {
            fixed[(RAW_PC + c) * n + row] = limb;
        };
        for (edges.items, 0..) |edge, logical| {
            const row = physical(logical, log_size);
            const values = executionTuple(edge, decoded);
            for (values, 0..) |value, c| fixed[c * n + row] = value;
            const pc = W.word(M, addresses.items[edge.id]);
            for (pc, 0..) |value, c| fixed[(RAW_PC + c) * n + row] = value;
        }
        fixed[FIRST * n + physical(0, log_size)] = M.one();
        fixed[LAST * n + physical(n - 1, log_size)] = M.one();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-rv64/index-control/unique-u64-static-address-superset/alu-binary/true-map-padding/v1\x00");
        var frame: [12]u8 = undefined;
        for (word_addresses, words) |pc, raw| {
            std.mem.writeInt(u64, frame[0..8], pc, .little);
            std.mem.writeInt(u32, frame[8..12], raw, .little);
            hash.update(&frame);
        }
        const owned_addresses = try addresses.toOwnedSlice(a);
        errdefer a.free(owned_addresses);
        const owned_edges = try edges.toOwnedSlice(a);
        errdefer a.free(owned_edges);
        return .{ .allocator = a, .words = words, .word_addresses = word_addresses, .contiguous = @import("../word16_cpu/rom.zig").contiguousAddresses(word_addresses), .decoded = decoded, .valid = valid, .admitted = admitted, .word_rows = word_rows, .row_words = row_words, .addresses = owned_addresses, .id_words = id_words, .first_rows = first_rows, .edges = owned_edges, .fixed = fixed, .log_size = log_size, .identity = hash.finalResult() };
    }
    pub fn deinit(self: *Authority) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.edges);
        self.allocator.free(self.first_rows);
        self.allocator.free(self.id_words);
        self.allocator.free(self.addresses);
        self.allocator.free(self.row_words);
        self.allocator.free(self.word_rows);
        self.allocator.free(self.admitted);
        self.allocator.free(self.valid);
        self.allocator.free(self.decoded);
        self.allocator.free(self.word_addresses);
        self.allocator.free(self.words);
        self.* = undefined;
    }
    pub fn metadataView(self: *const Authority) @import("../word16_cpu/rom.zig").MetadataView {
        return .{ .words = self.words, .addresses = self.word_addresses, .decoded = self.decoded, .word_rows = self.word_rows, .row_words = self.row_words, .admitted = self.admitted, .contiguous = self.contiguous, .log_size = self.log_size, .profile = .alu_binary_v2 };
    }
    pub fn idForPc(self: *const Authority, pc: u64) !u32 {
        return find(self.addresses, pc);
    }
    pub fn validatePair(self: *const Authority, id: u64, pc: u64) !void {
        if (id >= self.addresses.len or self.addresses[@intCast(id)] != pc) return error.InvalidIndexAddressPair;
    }
    pub fn executableId(self: *const Authority, pc: u64) !u32 {
        const id = try self.idForPc(pc);
        const word = self.id_words[id];
        if (word == NO_WORD or !self.admitted[word]) return error.NonfetchableIndexAddress;
        return id;
    }
    pub fn edgeFor(self: *const Authority, id: u32, taken: bool) !u32 {
        if (id >= self.addresses.len) return error.UnknownIndexAddress;
        const first = self.first_rows[id];
        if (!self.edges[first].executable) return error.NonfetchableIndexAddress;
        if (!taken) return first;
        const row = first + 1;
        if (row >= self.edges.len or self.edges[row].id != id or !self.edges[row].taken) return error.InvalidIndexBranchEdge;
        return row;
    }
};
fn find(addresses: []const u64, pc: u64) !u32 {
    var low: usize = 0;
    var high = addresses.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (addresses[mid] < pc) low = mid + 1 else high = mid;
    }
    if (low == addresses.len or addresses[low] != pc) return error.UnknownIndexAddress;
    return @intCast(low);
}
pub fn executionTuple(edge: Edge, decoded: []const Decoded) [EXECUTION_FIELDS]M {
    var values: [EXECUTION_FIELDS]M = @splat(M.zero());
    values[1] = M.fromCanonical(edge.id);
    if (!edge.executable) return values;
    const instruction = decoded[edge.word];
    const operation = Ops.classify(instruction.opcode).?;
    const effects = isa.effects(instruction.opcode);
    const ids = [_]u5{ if (effects.reads_rs1) instruction.rs1 else 0, if (effects.reads_rs2) instruction.rs2 else 0, if (effects.writes_rd) instruction.rd else 0 };
    values[0] = M.one();
    values[2] = M.fromCanonical(edge.next_id);
    values[3] = M.fromCanonical(operation.busId());
    for (ids, 0..) |id, slot| {
        values[4 + slot] = M.fromCanonical(id);
        values[7 + slot] = M.fromCanonical(@intFromBool(id == 0));
    }
    values[10] = M.fromCanonical(@intFromBool(operation.use_immediate));
    values[11] = M.fromCanonical(@intFromBool(operation.branch_predicate));
    if (operation.use_immediate) @memcpy(values[12..16], &W.word(M, @bitCast(instruction.imm)));
    values[16] = M.fromCanonical(@intFromBool(edge.taken));
    return values;
}
