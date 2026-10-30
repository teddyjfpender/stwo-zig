//! Original native PCS geometry from the v7 source policy alone. No legacy
//! admission, proof capture, or purported successful receipt is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("../prover/block_v7_native_source_v1.zig");
const Epoch = @import("../prover/block_v7_execution_epoch_v1.zig");
const Original = @import("../prover/block_v7_native_components_v1.zig");
const Fused = @import("../prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Kernel = @import("air/block_v6_partitioned_composition_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Limits = struct { shape: Shape.Limits = .{}, max_roster: usize = 1 << 16, max_parts: usize = 1 << 16 };
pub const Owned = struct {
    backing: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    pin: Source.Pin,
    epoch: Epoch.Epoch,
    roster: []const Epoch.Entry,
    limits: Limits,
    projections: []const @import("../prover/block_v5_native_projection_fused_source_v1.zig").Slot,
    slots: []const Memory.Slot,
    trace_count: usize,
    shape: Shape.Owned,
    constraint_count: usize,
    seal: [32]u8,
    pub fn derive(a: std.mem.Allocator, pin: Source.Pin, epoch: Epoch.Epoch, roster: []const Epoch.Entry, limits: Limits) !*Owned {
        if (roster.len == 0 or roster.len > limits.max_roster or limits.max_parts == 0) return error.NativeFixedProfileResourceLimit;
        try pin.validate();
        try epoch.requireEntry(roster, try pin.entry(a));
        if (!std.meta.eql(pin.template.config, epoch.config)) return error.InvalidV7NativeConfig;
        const out = try a.create(Owned);
        errdefer a.destroy(out);
        out.arena = std.heap.ArenaAllocator.init(a);
        errdefer out.arena.deinit();
        const temp = out.arena.allocator();
        var owned_pin = pin;
        const statement = try temp.create(@TypeOf(pin.shape.*));
        statement.* = pin.shape.*;
        // Pin.validate requires these slices to be empty. Retain no producer
        // allocation even when the original empty slice has a non-null pointer.
        statement.public_data.io_entries.input_words = &.{};
        statement.public_data.io_entries.output_words = &.{};
        owned_pin.shape = statement;
        var layout = try owned_pin.layout(temp);
        defer layout.deinit();
        const slots = try @import("../prover/block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(temp, statement, pin.frame, 1);
        if (layout.slots.len > limits.max_parts or slots.len > limits.max_parts) return error.NativeFixedProfileResourceLimit;
        // Zero sums describe shape only. They are never accepted as a proof.
        const claims = try temp.alloc(Fused.Claim, layout.slots.len);
        for (claims, layout.slots) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
        const memory = try temp.alloc(Memory.Claim, slots.len);
        for (memory) |*claim| claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .active_count = 0, .range_claims = @splat(Q.zero()) };
        const drawn = try epoch.draw(temp);
        var owner = try Original.Owner.init(temp, owned_pin, claims, memory, &drawn);
        defer owner.deinit();
        var combined = try owner.verifying();
        defer combined.deinit(temp);
        const count: usize = if (slots.len == 0) 3 else 4;
        const logs: [4][]const u32 = .{ owner.fixed, owner.main, if (count == 3) owner.interactions else owner.witness, owner.interactions };
        const all = core.air.components.Components{ .components = combined.handles, .n_preprocessed_columns = owner.fixed.len };
        var shape = try Shape.Owned.init(temp, logs[0..count], all, epoch.config, limits.shape);
        errdefer shape.deinit();
        var n: usize = 0;
        for (combined.handles) |component| n = try std.math.add(usize, n, component.nConstraints());
        const owned_roster = try temp.dupe(Epoch.Entry, roster);
        const projections = try temp.dupe(@TypeOf(layout.slots[0]), layout.slots);
        out.* = .{ .backing = a, .arena = out.arena, .pin = owned_pin, .epoch = epoch, .roster = owned_roster, .limits = limits, .projections = projections, .slots = slots, .trace_count = count, .shape = shape, .constraint_count = n, .seal = undefined };
        out.seal = try out.identity();
        return out;
    }
    pub fn context(self: *const Owned) Kernel.EquationContext {
        return .{ .shape = self.pin.shape, .external_retirements = self.pin.template.external_retirements, .register_custody_mode = 1, .projections = self.projections, .slots = self.slots, .tree_count = self.trace_count };
    }
    pub fn identity(self: *const Owned) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42374e46, 1, @intCast(self.trace_count), @intCast(self.constraint_count) });
        (try self.pin.entry(self.arena.child_allocator)).mix(&ch);
        ch.mixRoot(self.epoch.digest);
        ch.mixRoot(self.shape.deepProfile().identityDigest());
        ch.mixRoot(self.shape.friProfile().identityDigest());
        ch.mixU32s(&.{ self.shape.split, self.shape.composition_log, self.shape.mask_log, self.shape.lifting_log });
        for (self.shape.columns) |columns| {
            ch.mixU64(columns.len);
            ch.mixU32s(columns);
        }
        for (self.projections) |slot| @import("../prover/block_v5_native_projection_fused_source_v1.zig").mixSlot(&ch, slot);
        @import("../prover/block_execution_sidecar_batch_v2.zig").mixRoster(&ch, self.pin.index, try self.pin.template.identity(), self.slots);
        return ch.digestBytes();
    }
    pub fn validate(self: *const Owned) !void {
        if (!std.meta.eql(self.shape.config, self.epoch.config) or !std.meta.eql(self.seal, try self.identity())) return error.MutatedNativeFixedProfile;
        const expected = try derive(self.backing, self.pin, self.epoch, self.roster, self.limits);
        defer expected.deinit();
        if (!std.meta.eql(self.seal, expected.seal)) return error.UntrustedNativeFixedProfile;
    }
    pub fn sampleCount(self: *const Owned) !usize {
        var n: usize = 0;
        for (self.shape.layouts) |layout| n = try std.math.add(usize, n, layout.sampleCount());
        return n;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.backing;
        self.shape.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};

/// Finite four/five-commitment views for the exact PCS compilers. Original
/// shape validation remains on the owned source profile.
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 5) @compileError("v7 native has four/five commitments");
    return struct {
        pub const commitment_trees = N;
        original: *const Owned,
        columns: [N][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        pub fn init(original: *const Owned) !@This() {
            try original.validate();
            if (original.shape.columns.len != N or original.trace_count + 1 != N) return error.InvalidNativeFixedCommitments;
            return .{ .original = original, .columns = original.shape.columns[0..N].*, .widths = original.shape.widths, .config = original.epoch.config, .lifting_log = original.shape.lifting_log, .seal = original.seal };
        }
        pub fn validate(self: *const @This()) !void {
            const expected = try init(self.original);
            if (!std.meta.eql(self.seal, expected.seal) or !std.meta.eql(self.config, expected.config) or self.lifting_log != expected.lifting_log or !std.mem.eql(u32, self.widths, expected.widths)) return error.InvalidNativeFixedCommitments;
            for (self.columns, expected.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.InvalidNativeFixedCommitments;
        }
        pub fn deepProfile(self: *const @This()) @import("air/pcs_deep_circuit.zig").Profile {
            return self.original.shape.deepProfile();
        }
        pub fn friProfile(self: *const @This()) @import("air/fri_verifier_circuit.zig").Profile {
            return self.original.shape.friProfile();
        }
    };
}
