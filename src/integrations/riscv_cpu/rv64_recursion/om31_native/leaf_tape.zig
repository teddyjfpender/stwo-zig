//! Producer-only leaf seeds, emitted from independently verified native captures.
//! The circuit, transcript, PP and receiver are unchanged. A cache miss uses the
//! full graph; `check` compares every seed against that graph before reuse.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("mod.zig");
const Fold = @import("fold_tape.zig");
const Outer = @import("outer_wrap.zig");
const Components = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Types = @import("../../word16_global_execution/services/types.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
pub const Mode = enum { off, on, check };
pub fn mode() Mode {
    const value = std.posix.getenv("STWO_RV64_LEAF_SEED_TAPE") orelse return .off;
    if (std.mem.eql(u8, value, "check")) return .check;
    return if (std.mem.eql(u8, value, "1")) .on else .off;
}

const Key = struct {
    h: std.crypto.hash.sha2.Sha256,
    fn word(self: *Key, value: anytype) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, @intCast(value), .little);
        self.h.update(&bytes);
    }
    fn init(input: anytype, shape: *const V.Shape) Key {
        var self = Key{ .h = std.crypto.hash.sha2.Sha256.init(.{}) };
        self.h.update("rv64-om31-leaf-seed-class/v1\x00");
        self.h.update(@import("stwo_circuit_cpu_integration").om31.protocol.domainName());
        self.h.update(@tagName(Outer.shape()));
        self.h.update(&input.expected.fixed);
        if (input.fixed) |fixed| {
            self.h.update(&fixed.fixed_identity);
            self.h.update(&fixed.source_root);
            if (fixed.profile) |p| self.h.update(@tagName(p));
        }
        self.word(shape.global_log);
        self.word(shape.composition_log_split);
        self.word(shape.pcs.pow_bits);
        self.word(shape.pcs.fri_config.log_blowup_factor);
        self.word(shape.pcs.fri_config.n_queries);
        self.word(shape.pcs.fri_config.log_last_layer_degree_bound);
        self.word(shape.pcs.fri_config.fold_step);
        self.word(shape.pcs.lifting_log_size orelse 0);
        self.word(shape.nTrees());
        for (shape.tree_column_log_sizes, shape.mask_offsets) |logs, columns| {
            self.word(logs.len);
            for (logs, columns) |log, offsets| {
                self.word(log);
                self.word(offsets.len);
                for (offsets) |offset| self.word(@as(u32, @bitCast(offset)));
            }
        }
        return self;
    }
};

/// All class constants: source FIXED root, layout, exact GKR roster and proof
/// structure, config and outer profile. No producer-supplied class is admitted.
pub fn cpuClass(input: anytype, shape: *const V.Shape) ![32]u8 {
    var key = Key.init(input, shape);
    key.h.update("cpu\x00");
    key.h.update(&input.setup.key.root);
    const instances = input.expected.local_instances orelse return error.WideCpuLocalRequired;
    key.word(instances.len);
    for (instances) |instance| {
        for (Frame.originWords(instance.origin)) |w| key.word(w);
        key.word(instance.row_log);
        key.word(instance.terms);
        key.word(instance.fixed_offset);
        key.word(instance.main_offset);
    }
    const proof = (input.stage.local orelse return error.WideCpuLocalRequired).proof;
    key.word(proof.sumcheck_proofs.len);
    for (proof.sumcheck_proofs) |sc| {
        key.word(sc.round_polys.len);
        for (sc.round_polys) |p| key.word(p.coeffsSlice().len);
    }
    key.word(proof.layer_masks_by_instance.len);
    for (proof.layer_masks_by_instance) |masks| {
        key.word(masks.len);
        for (masks) |mask| key.word(mask.columns.len);
    }
    key.word(proof.output_claims_by_instance.len);
    for (proof.output_claims_by_instance) |claims| key.word(claims.len);
    return key.h.finalResult();
}
pub fn truthClass(input: anytype, shape: *const V.Shape) [32]u8 {
    var key = Key.init(input, shape);
    key.h.update("truth\x00");
    key.h.update(@tagName(std.meta.activeTag(input.truth)));
    key.h.update(&input.truth.key().root);
    key.word(input.truth.first());
    key.word(input.truth.count());
    return key.h.finalResult();
}

pub fn cpu(a: std.mem.Allocator, input: anytype, values: *const V.Captured) ![][4]u32 {
    var out: std.ArrayListUnmanaged([4]u32) = .empty;
    errdefer out.deinit(a);
    var emit = Fold.Emit{ .a = a, .out = &out };
    try emit.proof(values);
    // Same seed order as Cpu.Statement.init. Root/receipt exposure aliases
    // existing variables; arithmetic, byte extraction and inverse flags are hints.
    try emit.word(input.expected.ordinal);
    try emit.hash(input.expected.statement);
    try emit.hash(input.manifest.digest);
    const proof = (input.stage.local orelse return error.WideCpuLocalRequired).proof;
    for (proof.sumcheck_proofs) |sc| for (sc.round_polys) |poly| for (poly.coeffsSlice()) |v| try emit.om(v);
    for (proof.layer_masks_by_instance) |masks| for (masks) |mask| for (mask.columns) |pair| for (pair) |v| try emit.om(v);
    for (proof.output_claims_by_instance) |claims| for (claims) |v| try emit.om(v);
    for (input.encoded.claims) |v| try emit.om(v);
    const c = input.request.base.cpu;
    try emit.word(c.steps);
    try emit.word(input.request.base.epoch);
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        try emit.word(@as(u16, @truncate(c.initial_pc >> shift)));
        try emit.word(@as(u16, @truncate(c.final_pc >> shift)));
    }
    for (0..32) |r| {
        for (0..4) |i| {
            const shift: u6 = @intCast(16 * i);
            try emit.word(@as(u16, @truncate(c.initial_registers[r] >> shift)));
            try emit.word(@as(u16, @truncate(c.final_registers[r] >> shift)));
        }
        try emit.word(c.register_clocks[r]);
    }
    var plan = try Components.Plan.init(a, input.setup);
    defer plan.deinit();
    const ls = try input.setup.materials.geometry.lsCounts(input.request.base.memory.ls_count);
    const dword = try Types.dwordCounts(input.setup.bridges, input.request.ls_dword);
    try emit.word(input.request.sponge.first_id);
    for (plan.slots) |slot| {
        var rows: u32 = 0;
        var calls: u32 = 0;
        var first: u32 = 1;
        switch (slot.origin) {
            .core => |role| rows = switch (role) {
                .initial => @intCast(input.request.base.memory.initial.len),
                .terminal => @intCast(input.request.base.memory.terminal.len),
                .ls => ls.head,
                .ls_tail => ls.tail,
                .multiplication => input.request.base.multiplication_requests,
                .division => input.request.base.division_requests,
                else => 0,
            },
            .bridge => |family| {
                calls = input.request.calls[@intFromEnum(family)];
                first = input.first[@intFromEnum(family)];
            },
            .bulk => |kind| rows = input.request.bulk.rows(kind),
            .sponge => |kind| rows = input.request.sponge.rows(kind),
            .dword => |index| rows = dword[index],
        }
        try emit.word(rows);
        try emit.word(calls);
        try emit.word(first);
    }
    return out.toOwnedSlice(a);
}
pub fn truth(a: std.mem.Allocator, input: anytype, values: *const V.Captured) ![][4]u32 {
    var out: std.ArrayListUnmanaged([4]u32) = .empty;
    errdefer out.deinit(a);
    var emit = Fold.Emit{ .a = a, .out = &out };
    try emit.proof(values);
    try emit.word(input.expected.ordinal);
    try emit.word(input.truth.first());
    try emit.word(input.truth.count());
    try emit.hash(input.expected.statement);
    try emit.hash(input.manifest.digest);
    for (input.encoded.claims) |v| try emit.om(v);
    return out.toOwnedSlice(a);
}
pub fn compare(a: std.mem.Allocator, tape: []const [4]u32, ctx: *const V.common.Context) !void {
    // The fold comparator walks seed origins only and compares all coordinates.
    try Fold.compare(a, tape, ctx);
    std.debug.print("LEAF_SEED_TAPE check_ok seeds={}\n", .{tape.len});
}
