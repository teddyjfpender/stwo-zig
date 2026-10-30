//! Bounded transport of public union metadata. ELF, security, and complete
//! endpoint snapshots are independent receiver inputs. Decoding is never
//! admission: the union verifier reconstructs every shape and fixed root.
const std = @import("std");
const core = @import("stwo_core");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const Caller = @import("block_v7_caller_active_source_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const ShapeWire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const NativeRecord = struct {
    index: u32,
    /// Hex of the existing canonical finite BLAKE3 statement wire. Never
    /// serialize unused descriptor storage or uninitialized array tails.
    shape: []const u8,
    frame: @import("../air/block/memory_event.zig").Frame,
    template: @import("block_v5_native_template_protocol_v3.zig").Template,
    roots: [2][32]u8,
    access_root: [32]u8,
    expected_events: u64,
    layout_mode: Native.LayoutMode,
};
const CallerRecord = struct {
    index: u32,
    execution_index: u32,
    execution_identity: [32]u8,
    statement: @import("blake3_ethereum_sha_profile.zig").admission.Statement,
    total_steps: u32,
    frame: @import("../air/block/memory_event.zig").Frame,
    roots: [2][32]u8,
    access_root: [32]u8,
    config: core.pcs.PcsConfig,
};
fn flatten(comptime Out: type, value: anytype) Out {
    var out: Out = undefined;
    inline for (@typeInfo(Out).@"struct".fields) |field| {
        const v = @field(value, field.name);
        @field(out, field.name) = if (@typeInfo(@TypeOf(v)) == .pointer) v.* else v;
    }
    return out;
}
pub fn ForMode(comptime window: bool) type {
    const Statement = @import("block_v7_multi_union_statement_v1.zig").ForMode(window);
    return struct {
        pub const Limits = struct { bytes: usize = 16 << 20, decode_bytes: usize = 128 << 20, reconstruction_bytes: usize = 512 << 20 };
        pub const Data = struct {
            schema: []const u8,
            window: bool,
            epoch: @import("block_v7_execution_epoch_v1.zig").Epoch,
            entries: []const @import("block_v7_execution_epoch_v1.zig").Entry,
            natives: []const NativeRecord,
            callers: []const CallerRecord,
            program_plan: @import("block_v5_program_table_v1.zig").Plan,
            program_roots: [2][32]u8,
            lookup_plan: @import("block_v5_native_lookup_plan_v1.zig").Plan,
            lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
            lookup_roots: [2][32]u8,
            memory_roots: [2][32]u8,
            memory_geometry: []const @import("block_v5_ram_lanes_protocol_v1.zig").Claim,
            interval_log: u32,
            selected_initial_addresses: []const u32,
        };
        const SCHEMA = "stwo-v7-union-public-metadata-v2";
        /// Address selection only. Values always come from independently
        /// pinned complete endpoint states; omission is checked by the AIR.
        pub fn selectionAddresses(a: std.mem.Allocator, bytes: []const u8, limits: Limits) ![]u32 {
            if (limits.bytes == 0 or limits.decode_bytes == 0 or bytes.len > limits.bytes) return error.UnionMetadataSizeLimit;
            const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
            defer budget.destroy();
            const parsed = try std.json.parseFromSlice(Data, budget.allocator(), bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes });
            defer parsed.deinit();
            const d = parsed.value;
            if (!std.mem.eql(u8, d.schema, SCHEMA) or d.window != window or d.natives.len == 0 or d.natives.len > 64 or d.callers.len > d.natives.len or d.entries.len > 131) return error.InvalidUnionMetadata;
            return a.dupe(u32, d.selected_initial_addresses);
        }
        pub fn encode(a: std.mem.Allocator, statement: *const Statement.Owned, limits: Limits) ![]u8 {
            if (limits.bytes == 0 or limits.decode_bytes == 0) return error.InvalidUnionMetadataLimits;
            const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
            defer budget.destroy();
            var arena = std.heap.ArenaAllocator.init(budget.allocator());
            defer arena.deinit();
            const t = arena.allocator();
            const i = statement.input;
            const natives = try t.alloc(NativeRecord, i.natives.len);
            defer t.free(natives);
            for (natives, i.natives) |*out, pin| {
                var shape = Writer.init(t, limits.bytes);
                defer shape.deinit();
                try ShapeWire.encodeBlake3Statement(&shape, pin.shape, .{});
                const hex = try t.alloc(u8, try std.math.mul(usize, 2, shape.bytes.items.len));
                const digits = "0123456789abcdef";
                for (shape.bytes.items, 0..) |byte, index| {
                    hex[2 * index] = digits[byte >> 4];
                    hex[2 * index + 1] = digits[byte & 15];
                }
                inline for (@typeInfo(NativeRecord).@"struct".fields) |field| @field(out, field.name) = if (comptime std.mem.eql(u8, field.name, "shape")) hex else @field(pin, field.name);
            }
            const callers = try t.alloc(CallerRecord, i.callers.len);
            defer t.free(callers);
            for (callers, i.callers) |*out, pin| out.* = flatten(CallerRecord, pin);
            const addresses: []const u32 = if (statement.trusted.window) |w| if (w.selection) |s| s.addresses else &.{} else &.{};
            var program_plan = i.program_plan;
            // Immutable ROM is reconstructed from the independently pinned ELF.
            // Only its input-dependent multiplicities belong in this package.
            program_plan.leaves = &.{};
            const data = Data{ .schema = SCHEMA, .window = window, .epoch = i.epoch, .entries = i.entries, .natives = natives, .callers = callers, .program_plan = program_plan, .program_roots = i.program_roots, .lookup_plan = i.lookup_plan, .lookup_layout = i.lookup_layout, .lookup_roots = i.lookup_roots, .memory_roots = i.memory_roots, .memory_geometry = i.memory_geometry, .interval_log = i.interval_log, .selected_initial_addresses = addresses };
            const bytes = try std.json.Stringify.valueAlloc(t, data, .{});
            defer t.free(bytes);
            if (bytes.len > limits.bytes) return error.UnionMetadataSizeLimit;
            return a.dupe(u8, bytes);
        }
        pub fn decode(a: std.mem.Allocator, bytes: []const u8, trusted: Receiver.Trusted, limits: Limits) !*Statement.Owned {
            if (limits.bytes == 0 or limits.decode_bytes == 0 or limits.reconstruction_bytes == 0 or bytes.len > limits.bytes) return error.UnionMetadataSizeLimit;
            if ((trusted.window != null) != window) return error.InvalidUnionMetadata;
            const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
            defer budget.destroy();
            var arena = std.heap.ArenaAllocator.init(budget.allocator());
            defer arena.deinit();
            const t = arena.allocator();
            const parsed = try std.json.parseFromSlice(Data, t, bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes });
            defer parsed.deinit();
            const d = parsed.value;
            if (!std.mem.eql(u8, d.schema, SCHEMA) or d.window != window or d.natives.len == 0 or d.natives.len > 64 or d.callers.len > d.natives.len or d.entries.len > 131) return error.InvalidUnionMetadata;
            const selected: []const u32 = if (trusted.window) |w| if (w.selection) |s| s.addresses else &.{} else &.{};
            if (!std.mem.eql(u32, selected, d.selected_initial_addresses)) return error.UntrustedUnionInitializationSelection;
            const natives = try t.alloc(Native.Pin, d.natives.len);
            defer t.free(natives);
            for (natives, d.natives) |*pin, *record| {
                if (record.shape.len % 2 != 0) return error.InvalidUnionShapeWire;
                const raw = try t.alloc(u8, record.shape.len / 2);
                _ = try std.fmt.hexToBytes(raw, record.shape);
                const shape = try t.create(ShapeWire.OwnedBlake3Statement);
                shape.* = try ShapeWire.decodeBlake3Statement(t, raw, .{});
                inline for (@typeInfo(Native.Pin).@"struct".fields) |field| @field(pin, field.name) = if (comptime std.mem.eql(u8, field.name, "shape")) &shape.value else @field(record, field.name);
            }
            const callers = try t.alloc(Caller.Pin, d.callers.len);
            defer t.free(callers);
            for (callers, d.callers) |*pin, *record| {
                inline for (@typeInfo(Caller.Pin).@"struct".fields) |field| @field(pin, field.name) = if (comptime std.mem.eql(u8, field.name, "statement")) &record.statement else @field(record, field.name);
            }
            if (d.program_plan.leaves.len != 0) return error.UnexpectedSerializedUnionRom;
            // Reconstruction owns a separate, explicitly bounded ordinary
            // allocator. Hash-map resizing and ELF scratch must be reclaimed
            // immediately, rather than accumulating in the parsing arena.
            const reconstruction = try Budget.createRetainingParent(a, limits.reconstruction_bytes);
            defer reconstruction.destroy();
            const r = reconstruction.allocator();
            var initial: ?@import("block_v7_initial_intervals_v1.zig").Owned = if (trusted.window == null) try Receiver.deriveInitialization(r, trusted, .{}) else null;
            defer if (initial) |*owned| owned.deinit();
            const policy = if (trusted.window) |w| &w.initial else &initial.?;
            var image = try @import("block_v7_program_image_v1.zig").Owned.init(r, trusted.elf, policy, .{});
            defer image.deinit();
            if (!std.meta.eql(image.root, d.program_plan.program_root)) return error.UntrustedUnionProgramImage;
            var program_plan = d.program_plan;
            program_plan.leaves = image.leaves;
            return Statement.Owned.init(a, trusted, .{ .epoch = d.epoch, .entries = d.entries, .natives = natives, .callers = callers, .program_plan = program_plan, .program_roots = d.program_roots, .lookup_plan = d.lookup_plan, .lookup_layout = d.lookup_layout, .lookup_roots = d.lookup_roots, .memory_roots = d.memory_roots, .memory_geometry = d.memory_geometry, .interval_log = d.interval_log });
        }
    };
}
