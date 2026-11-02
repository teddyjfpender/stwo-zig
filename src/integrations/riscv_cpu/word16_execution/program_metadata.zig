//! Immutable owned Entry/maps, independent of request geometry and image lifetime.
//! Raw words/addresses are never retained: each Program keeps its current image
//! view. Entry.raw/pc copies, profile and features bind every cache match exactly.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const engine = @import("stwo_prover_engine");
const X = front.rv64_air.word16_execution;
const Entry = X.features.Entry;
const Profile = front.rv64.execution_profile.Profile;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Input = struct { words: []const u32, addresses: []const u64, profile: Profile, identity: ?[32]u8 = null };
pub const Data = struct {
    entries: []const Entry,
    word_rows: []const u32,
    row_to_entry: []const u32,
    row_taken: []const bool,
    log_size: u32,
    opcodes: [@import("program.zig").OPCODE_COUNT]bool,
    contiguous: bool,
    fn payloadBytes(self: Data) !usize {
        var size = try std.math.mul(usize, self.entries.len, @sizeOf(Entry));
        size = try std.math.add(usize, size, try std.math.mul(usize, self.word_rows.len, @sizeOf(u32)));
        size = try std.math.add(usize, size, try std.math.mul(usize, self.row_to_entry.len, @sizeOf(u32)));
        return std.math.add(usize, size, self.row_taken.len * @sizeOf(bool));
    }
    fn free(self: Data, a: std.mem.Allocator) void {
        a.free(self.row_taken);
        a.free(self.row_to_entry);
        a.free(self.word_rows);
        a.free(self.entries);
    }
    fn validate(self: Data, input: Input) !void {
        if (input.words.len == 0 or input.words.len != input.addresses.len or self.entries.len != input.words.len or self.word_rows.len != self.entries.len or self.row_to_entry.len != self.row_taken.len) return error.InvalidProgramMetadataShape;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-rv64/full-word16/program-rom/v1\x00");
        const features = X.features.identity();
        hash.update(&features);
        if (X.features.zbbProfile(input.profile)) hash.update(&X.features.zbbIdentity());
        var framed: [12]u8 = undefined;
        std.mem.writeInt(u32, framed[0..4], @intFromEnum(input.profile), .little);
        std.mem.writeInt(u64, framed[4..12], input.words.len, .little);
        hash.update(&framed);
        var count: usize = 0;
        var opcodes: [@import("program.zig").OPCODE_COUNT]bool = @splat(false);
        for (self.entries, self.word_rows, input.words, input.addresses, 0..) |entry, first, raw, pc, i| {
            if (entry.raw != raw or entry.pc != pc or first != count) return error.InvalidProgramMetadataIdentity;
            var canonical: Entry = .{ .raw = raw, .pc = pc, .instruction = .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0 } };
            if (front.rv64.execution_profile.decode(input.profile, raw)) |instruction| {
                if (front.rv64.execution_profile.admitted(input.profile, instruction.opcode)) canonical = Entry.fromInstructionFor(input.profile, raw, pc, instruction);
            } else |_| {}
            if (!std.meta.eql(entry, canonical)) return error.InvalidProgramMetadataIdentity;
            std.mem.writeInt(u64, framed[0..8], pc, .little);
            std.mem.writeInt(u32, framed[8..12], raw, .little);
            hash.update(&framed);
            const rows: usize = if (entry.hasTakenEdge()) 2 else 1;
            const end = try std.math.add(usize, count, rows);
            if (end > self.row_to_entry.len) return error.InvalidProgramMetadataShape;
            for (count..end) |row| if (self.row_to_entry[row] != i or self.row_taken[row] != (row != count)) return error.InvalidProgramMetadataShape;
            count = end;
            if (entry.valid) opcodes[@intFromEnum(entry.instruction.opcode)] = true;
        }
        const identity = input.identity orelse return error.InvalidProgramMetadataIdentity;
        const actual_identity = hash.finalResult();
        if (!std.mem.eql(u8, &identity, &actual_identity)) return error.InvalidProgramMetadataIdentity;
        if (count > @as(usize, 1) << 22) return error.InvalidProgramMetadataShape;
        if (count == 0 or count != self.row_to_entry.len or self.log_size != @max(X.layout.MIN_LOG, std.math.log2_int_ceil(usize, count)) or !std.mem.eql(bool, &opcodes, &self.opcodes)) return error.InvalidProgramMetadataShape;
        if (self.contiguous != front.rv64_air.word16_cpu.rom.contiguousAddresses(input.addresses)) return error.InvalidProgramMetadataIdentity;
    }
};
const Node = struct {
    identity: [32]u8,
    features: [32]u8,
    profile: Profile,
    data: Data,
    payload_allocator: std.mem.Allocator,
    payload_budget: ?*Budget,
    payload_bytes: usize,
    fn matches(self: *const Node, input: Input, features: [32]u8) bool {
        if (self.profile != input.profile or !std.mem.eql(u8, &self.features, &features) or input.words.len != input.addresses.len or self.data.entries.len != input.words.len) return false;
        if (input.identity) |identity| if (!std.mem.eql(u8, &self.identity, &identity)) return false;
        for (self.data.entries, input.words, input.addresses) |entry, raw, pc| if (entry.raw != raw or entry.pc != pc) return false;
        return true;
    }
};
const State = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Thread.Mutex = .{},
    limit: usize,
    nodes: std.ArrayList(*Node) = .empty,
    payload_bytes: usize = 0,
    hits: u64 = 0,
    metadata_bytes_not_rebuilt: u64 = 0,
    duplicate_metadata_bytes_released: u64 = 0,
    fn retain(self: *State) void {
        const prior = self.references.fetchAdd(1, .monotonic);
        if (prior >= std.math.maxInt(usize) / 2) @panic("too many program metadata leases");
    }
    fn release(self: *State) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const a = self.allocator;
        const budget = self.budget;
        for (self.nodes.items) |node| {
            const payload_budget = node.payload_budget;
            node.data.free(node.payload_allocator);
            a.destroy(node);
            if (payload_budget) |owner| owner.destroy();
        }
        self.nodes.deinit(a);
        a.destroy(self);
        if (budget) |owner| owner.destroy();
    }
    fn retainedBytes(self: *const State) usize {
        return @sizeOf(State) + self.nodes.capacity * @sizeOf(*Node) + self.nodes.items.len * @sizeOf(Node) + self.payload_bytes;
    }
};
pub const Lease = struct {
    state: *State,
    node: *const Node,
    pub fn identity(self: *const Lease) [32]u8 {
        return self.node.identity;
    }
    pub fn view(self: *const Lease) Data {
        return self.node.data;
    }
    pub fn deinit(self: *Lease) void {
        self.state.release();
        self.* = undefined;
    }
};
pub const Snapshot = struct {
    limit_bytes: usize = 0,
    retained_bytes: usize = 0,
    payload_bytes: usize = 0,
    programs: usize = 0,
    hits: u64 = 0,
    metadata_bytes_not_rebuilt: u64 = 0,
    duplicate_metadata_bytes_released: u64 = 0,
    owner_leases: usize = 0,
};
pub const OwnedAllocation = struct { kind: enum { program_metadata, metadata }, address: usize, bytes: usize };
pub const Cache = struct {
    state: ?*State,
    pub fn init(a: std.mem.Allocator, limit: usize) !Cache {
        if (limit == 0) return .{ .state = null };
        if (limit < @sizeOf(State)) return error.InvalidProgramMetadataBudget;
        const budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (budget) |owner| owner.destroy();
        const state = try a.create(State);
        state.* = .{ .allocator = a, .budget = budget, .limit = limit };
        return .{ .state = state };
    }
    pub fn deinit(self: *Cache) void {
        if (self.state) |state| state.release();
        self.* = undefined;
    }
    pub fn snapshot(self: *const Cache) Snapshot {
        const state = self.state orelse return .{};
        state.mutex.lock();
        defer state.mutex.unlock();
        return .{ .limit_bytes = state.limit, .retained_bytes = state.retainedBytes(), .payload_bytes = state.payload_bytes, .programs = state.nodes.items.len, .hits = state.hits, .metadata_bytes_not_rebuilt = state.metadata_bytes_not_rebuilt, .duplicate_metadata_bytes_released = state.duplicate_metadata_bytes_released, .owner_leases = state.references.load(.acquire) };
    }
    pub fn lookup(self: *const Cache, input: Input) !?Lease {
        const state = self.state orelse return null;
        const features = X.features.identity();
        state.mutex.lock();
        defer state.mutex.unlock();
        for (state.nodes.items) |node| if (node.matches(input, features)) {
            const hits = try std.math.add(u64, state.hits, 1);
            const avoided = try std.math.add(u64, state.metadata_bytes_not_rebuilt, node.payload_bytes);
            state.retain();
            state.hits = hits;
            state.metadata_bytes_not_rebuilt = avoided;
            return .{ .state = state, .node = node };
        };
        return null;
    }
    /// Internal Program-construction hook. Success with a lease consumes all
    /// four metadata arrays, including on a concurrent duplicate hit. Null or
    /// error leaves every input owner unchanged. Raw arrays/fixed matrix stay
    /// with the Program and never enter this owner.
    pub fn adopt(self: *const Cache, input: Input, data: Data, payload_allocator: std.mem.Allocator) !?Lease {
        const state = self.state orelse return null;
        const identity = input.identity orelse return error.InvalidProgramMetadataIdentity;
        try data.validate(input);
        const bytes = try data.payloadBytes();
        const features = X.features.identity();
        state.mutex.lock();
        defer state.mutex.unlock();
        for (state.nodes.items) |node| if (node.matches(input, features)) {
            const hits = try std.math.add(u64, state.hits, 1);
            const freed = try std.math.add(u64, state.duplicate_metadata_bytes_released, bytes);
            state.retain();
            state.hits = hits;
            state.duplicate_metadata_bytes_released = freed;
            data.free(payload_allocator);
            return .{ .state = state, .node = node };
        };
        const wanted = try std.math.add(usize, state.nodes.items.len, 1);
        const control = try std.math.add(usize, @sizeOf(State), try std.math.mul(usize, @max(state.nodes.capacity, wanted), @sizeOf(*Node)));
        const headers = try std.math.mul(usize, wanted, @sizeOf(Node));
        const payload = try std.math.add(usize, state.payload_bytes, bytes);
        if (try std.math.add(usize, control, try std.math.add(usize, headers, payload)) > state.limit) return null;
        const node = try state.allocator.create(Node);
        errdefer state.allocator.destroy(node);
        try state.nodes.ensureTotalCapacityPrecise(state.allocator, wanted);
        // No fallible work remains: transfer once, then publish immutable data.
        node.* = .{ .identity = identity, .features = features, .profile = input.profile, .data = data, .payload_allocator = payload_allocator, .payload_budget = if (Budget.fromAllocator(payload_allocator)) |owner| owner.retain() else null, .payload_bytes = bytes };
        state.nodes.appendAssumeCapacity(node);
        state.payload_bytes = payload;
        state.retain();
        return .{ .state = state, .node = node };
    }
    pub fn ownedAllocations(self: *const Cache, a: std.mem.Allocator) ![]OwnedAllocation {
        const state = self.state orelse return a.alloc(OwnedAllocation, 0);
        state.mutex.lock();
        defer state.mutex.unlock();
        const out = try a.alloc(OwnedAllocation, 2 + 5 * state.nodes.items.len);
        out[0] = .{ .kind = .metadata, .address = @intFromPtr(state), .bytes = @sizeOf(State) };
        out[1] = .{ .kind = .metadata, .address = if (state.nodes.capacity == 0) 0 else @intFromPtr(state.nodes.items.ptr), .bytes = state.nodes.capacity * @sizeOf(*Node) };
        for (state.nodes.items, 0..) |node, i| {
            out[2 + 5 * i] = .{ .kind = .metadata, .address = @intFromPtr(node), .bytes = @sizeOf(Node) };
            out[3 + 5 * i] = .{ .kind = .program_metadata, .address = @intFromPtr(node.data.entries.ptr), .bytes = node.data.entries.len * @sizeOf(Entry) };
            out[4 + 5 * i] = .{ .kind = .program_metadata, .address = @intFromPtr(node.data.word_rows.ptr), .bytes = node.data.word_rows.len * @sizeOf(u32) };
            out[5 + 5 * i] = .{ .kind = .program_metadata, .address = @intFromPtr(node.data.row_to_entry.ptr), .bytes = node.data.row_to_entry.len * @sizeOf(u32) };
            out[6 + 5 * i] = .{ .kind = .program_metadata, .address = @intFromPtr(node.data.row_taken.ptr), .bytes = node.data.row_taken.len * @sizeOf(bool) };
        }
        return out;
    }
};
