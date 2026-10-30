//! Bounded, request-pruned symbolic wire selection. No witness values are read
//! while compiling. Every MAIN dependency must have a prior device write phase.
const std = @import("std");
pub const Registry = @import("resident_parent_wire_registry_v1.zig");
pub const Instruction = Registry.Expr;
pub const Candidate = extern struct { weight: u32, coordinates: [4]u32 };
pub const Request = extern struct { first: u32, count: u32, candidate_first: u32, candidate_count: u32, weight: u32, output_first: u32, phase: u32 };
pub const Proposal = struct { consumer: Registry.Consumer, phase: u32 };
pub const Ready = struct { main_word: u32, phase: u32 };
pub const Limits = struct { max_requests: usize = 1 << 20, max_instructions: usize = 1 << 25, max_per_request: usize = 4096, max_bytes: usize = 1 << 30 };
pub const Plan = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    instructions: []Instruction,
    candidates: []Candidate,
    requests: []Request,
    main_words: usize,
    scratch_words: usize,
    output_words: usize,
    device_bytes: usize,
    identity: [32]u8,
    pub fn init(backing: std.mem.Allocator, registry: *const Registry.Plan, proposals: []const Proposal, ready: []const Ready, limits: Limits) !Plan {
        if (proposals.len == 0 or proposals.len > limits.max_requests or proposals.len > std.math.maxInt(u32) / 4 or limits.max_instructions > std.math.maxInt(u32)) return error.ResidentWireResolveResourceLimit;
        for (ready, 0..) |r, i| if (r.main_word >= registry.main_words or (i != 0 and ready[i - 1].main_word >= r.main_word)) return error.InvalidResidentWireReadyOrder;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var ins: std.ArrayList(Instruction) = .empty;
        var candidates: std.ArrayList(Candidate) = .empty;
        const requests = try a.alloc(Request, proposals.len);
        const needed = try backing.alloc(bool, registry.expressions.len);
        defer backing.free(needed);
        const remap = try backing.alloc(u32, registry.expressions.len);
        defer backing.free(remap);
        for (proposals, requests, 0..) |proposal, *out, ordinal| {
            if (ordinal != 0 and proposals[ordinal - 1].phase > proposal.phase) return error.InvalidResidentWireResolvePhase;
            const accepted = (try registry.consumer(proposal.consumer.main_word)) orelse return error.UntrustedResidentWireConsumer;
            if (!std.meta.eql(accepted, proposal.consumer)) return error.UntrustedResidentWireConsumer;
            const weight_expression = registry.expressions[accepted.weight];
            const inactive = weight_expression.op == @intFromEnum(Registry.Op.constant) and weight_expression.value == 0;
            const endpoint = if (inactive) null else registry.endpoint(accepted.endpoint);
            @memset(needed, false);
            needed[accepted.weight] = true;
            if (endpoint) |e| for (registry.candidates[e.first..][0..e.count]) |candidate| {
                needed[candidate.weight] = true;
                for (candidate.coordinates) |v| needed[v] = true;
            };
            var i = needed.len;
            while (i != 0) {
                i -= 1;
                if (!needed[i]) continue;
                const e = registry.expressions[i];
                switch (@as(Registry.Op, @enumFromInt(e.op))) {
                    .constant, .main => {},
                    .neg => needed[e.lhs] = true,
                    .add, .sub, .mul => {
                        needed[e.lhs] = true;
                        needed[e.rhs] = true;
                    },
                }
            }
            const first = ins.items.len;
            for (registry.expressions, 0..) |expression, index| {
                if (!needed[index]) continue;
                var e = expression;
                switch (@as(Registry.Op, @enumFromInt(e.op))) {
                    .constant => {},
                    .main => {
                        const phase = readyPhase(ready, e.value) orelse return error.UninitializedResidentWireDependency;
                        if (phase >= proposal.phase) return error.FutureResidentWireDependency;
                    },
                    .neg => e.lhs = remap[e.lhs],
                    .add, .sub, .mul => {
                        e.lhs = remap[e.lhs];
                        e.rhs = remap[e.rhs];
                    },
                }
                remap[index] = @intCast(ins.items.len);
                try ins.append(a, e);
                if (ins.items.len > limits.max_instructions or ins.items.len - first > limits.max_per_request) return error.ResidentWireResolveResourceLimit;
            }
            const cf = candidates.items.len;
            if (endpoint) |e| for (registry.candidates[e.first..][0..e.count]) |candidate| {
                var c: Candidate = .{ .weight = remap[candidate.weight], .coordinates = undefined };
                for (candidate.coordinates, &c.coordinates) |v, *dest| dest.* = remap[v];
                try candidates.append(a, c);
            };
            out.* = .{ .first = @intCast(first), .count = @intCast(ins.items.len - first), .candidate_first = @intCast(cf), .candidate_count = @intCast(candidates.items.len - cf), .weight = remap[accepted.weight], .output_first = @intCast(ordinal * 4), .phase = proposal.phase };
        }
        const bytes = try std.math.add(usize, try std.math.mul(usize, ins.items.len, @sizeOf(Instruction) + 4), try std.math.add(usize, try std.math.mul(usize, candidates.items.len, @sizeOf(Candidate)), try std.math.mul(usize, requests.len, @sizeOf(Request) + 16)));
        if (bytes > limits.max_bytes) return error.ResidentWireResolveResourceLimit;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo/resident-wire-resolve/v1\x00");
        h.update(&registry.program_id);
        h.update(std.mem.sliceAsBytes(ins.items));
        h.update(std.mem.sliceAsBytes(candidates.items));
        h.update(std.mem.sliceAsBytes(requests));
        const scratch_words = ins.items.len;
        return .{ .a = backing, .arena = arena, .instructions = try ins.toOwnedSlice(a), .candidates = try candidates.toOwnedSlice(a), .requests = requests, .main_words = registry.main_words, .scratch_words = scratch_words, .output_words = proposals.len * 4, .device_bytes = bytes, .identity = h.finalResult() };
    }
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn readyPhase(ready: []const Ready, word: u32) ?u32 {
    var lo: usize = 0;
    var hi = ready.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (ready[mid].main_word < word) lo = mid + 1 else hi = mid;
    }
    return if (lo < ready.len and ready[lo].main_word == word) ready[lo].phase else null;
}
