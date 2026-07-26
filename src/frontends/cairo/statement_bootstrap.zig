//! Canonical statement-side transcript inputs for a Cairo proof.
//!
//! This module deliberately stops before commitments, interaction claims,
//! OODS, FRI, and query data. The component-enable and flattened-log-size
//! claims may be supplied directly or derived from the complete canonical
//! composition schedule. `CairoProofPlan` alone does not yet model the complete
//! optional Cairo claim.

const std = @import("std");
const adapter = @import("adapter/mod.zig");
const claim_registry = @import("air/official_claim_registry.zig");
const public_data = @import("statement/public_data.zig");
const composition_bundle = @import("witness/composition_bundle.zig");

pub const ORDINALS = [_]u32{ 1, 2, 10, 11, 12, 13, 14, 15, 16 };
pub const compact_statement_magic = "STWZCS1\x00".*;
pub const compact_statement_version: u16 = 1;
pub const compact_statement_header_bytes: usize = 80;
pub const compact_statement_memory_entry_words: usize = 9;

pub const PcsConfig = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    n_queries: u32,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    lifting_log_size: ?u32 = null,
};

pub const StatementBootstrapInput = struct {
    channel_salt: u32,
    pcs: PcsConfig,
    component_enable_bits: []const bool,
    component_log_sizes: []const u32,
    prover_input: *const adapter.ProverInput,
};

pub const ScheduledStatementBootstrapInput = struct {
    channel_salt: u32,
    pcs: PcsConfig,
    composition: *const composition_bundle.Bundle,
    prover_input: *const adapter.ProverInput,
};

pub const Error = error{
    ClaimLengthOverflow,
    InvalidClaimWord,
    InvalidClaimGeometry,
    DuplicateClaimComponent,
    InvalidMemoryId,
    InvalidOutputSegment,
    InvalidProgramRange,
    InvalidPublicSegmentContext,
    InvalidSafeCall,
    MemoryAddressMissing,
    SegmentPointerOverflow,
    UnknownClaimComponent,
};

pub const OwnedFlatClaimGeometry = struct {
    allocator: std.mem.Allocator,
    component_enable_bits: []bool,
    component_log_sizes: []u32,

    pub fn deinit(self: *OwnedFlatClaimGeometry) void {
        self.allocator.free(self.component_enable_bits);
        self.allocator.free(self.component_log_sizes);
        self.* = undefined;
    }
};

/// One active field from the canonical Rust `CairoClaim`. Dynamic fields carry
/// their claim log. Fixed fields may omit it; when present it must equal the
/// version-pinned registry value. `instance` is nonzero only for the contiguous
/// `memory_id_to_big` prefix.
pub const CanonicalClaimComponent = struct {
    name: []const u8,
    instance: u32 = 0,
    log_size: ?u32 = null,
};

/// Reconstructs Rust `CairoClaim::flatten_claim` from canonical active fields.
/// This is the diagnostic import boundary for a Rust-derived claim and the
/// production boundary for the eventual Zig claim generator.
pub fn deriveFlatClaimGeometryFromCanonical(
    allocator: std.mem.Allocator,
    components: []const CanonicalClaimComponent,
) (Error || std.mem.Allocator.Error)!OwnedFlatClaimGeometry {
    const enable_bits = try allocator.alloc(bool, claim_registry.enable_slot_count);
    errdefer allocator.free(enable_bits);
    @memset(enable_bits, false);
    const log_sizes = try allocator.alloc(u32, components.len);
    errdefer allocator.free(log_sizes);
    const consumed = try allocator.alloc(bool, components.len);
    defer allocator.free(consumed);
    @memset(consumed, false);

    var log_cursor: usize = 0;
    var memory_prefix_ended = false;
    for (claim_registry.enable_slots) |slot| {
        const field = claim_registry.claim_fields[slot.claim_field_index];
        var found: ?usize = null;
        for (components, 0..) |component, component_index| {
            if (!std.mem.eql(u8, component.name, field.name) or
                component.instance != slot.field_slot_index)
                continue;
            if (found != null) return Error.DuplicateClaimComponent;
            found = component_index;
        }

        if (slot.log_size_shape == .special_dynamic_prefix) {
            if (found == null) {
                memory_prefix_ended = true;
            } else if (memory_prefix_ended) {
                return Error.InvalidClaimGeometry;
            }
        }
        const component_index = found orelse continue;
        if (consumed[component_index]) return Error.DuplicateClaimComponent;
        const component = components[component_index];
        const log_size = switch (slot.log_size_shape) {
            .dynamic, .special_dynamic_prefix => component.log_size orelse return Error.InvalidClaimGeometry,
            .fixed => fixed: {
                const expected = slot.fixed_log_size orelse
                    return Error.InvalidClaimGeometry;
                if (component.log_size) |actual| {
                    if (actual != expected) return Error.InvalidClaimGeometry;
                }
                break :fixed expected;
            },
        };
        try validateClaimWord(log_size);
        consumed[component_index] = true;
        enable_bits[slot.enable_slot] = true;
        log_sizes[log_cursor] = log_size;
        log_cursor += 1;
    }
    for (consumed) |was_consumed| if (!was_consumed) return Error.UnknownClaimComponent;
    if (log_cursor != log_sizes.len) return Error.InvalidClaimGeometry;

    return .{
        .allocator = allocator,
        .component_enable_bits = enable_bits,
        .component_log_sizes = log_sizes,
    };
}

/// Owns all statement transcript inputs emitted by `init`.
pub const OwnedStatementBootstrap = struct {
    allocator: std.mem.Allocator,
    ordinal_1: []u32,
    ordinal_2: []u32,
    ordinal_10: []u32,
    ordinal_11: []u32,
    ordinal_12: []u32,
    ordinal_13: []u32,
    ordinal_14: []u32,
    ordinal_15: []u32,
    ordinal_16: []u32,

    pub fn deinit(self: *OwnedStatementBootstrap) void {
        self.allocator.free(self.ordinal_1);
        self.allocator.free(self.ordinal_2);
        self.allocator.free(self.ordinal_10);
        self.allocator.free(self.ordinal_11);
        self.allocator.free(self.ordinal_12);
        self.allocator.free(self.ordinal_13);
        self.allocator.free(self.ordinal_14);
        self.allocator.free(self.ordinal_15);
        self.allocator.free(self.ordinal_16);
        self.* = undefined;
    }

    pub fn words(self: *const OwnedStatementBootstrap, ordinal: u32) ?[]const u32 {
        return switch (ordinal) {
            1 => self.ordinal_1,
            2 => self.ordinal_2,
            10 => self.ordinal_10,
            11 => self.ordinal_11,
            12 => self.ordinal_12,
            13 => self.ordinal_13,
            14 => self.ordinal_14,
            15 => self.ordinal_15,
            16 => self.ordinal_16,
            else => null,
        };
    }

    /// Populates the statement bindings of a Metal `TranscriptRecipe`.
    /// Kept structural so this frontend module does not depend on Metal; the
    /// recipient must provide `loadInputWords(ordinal, words)`.
    pub fn populateTranscriptRecipeInputs(
        self: *const OwnedStatementBootstrap,
        recipe: anytype,
    ) !void {
        inline for (ORDINALS) |ordinal| {
            try recipe.loadInputWords(ordinal, self.words(ordinal).?);
        }
    }
};

/// Preferred constructor when the validated canonical composition schedule is
/// available. No claim words are imported from a Rust proof.
pub fn initFromCompositionSchedule(
    allocator: std.mem.Allocator,
    input: ScheduledStatementBootstrapInput,
) (Error || std.mem.Allocator.Error)!OwnedStatementBootstrap {
    var flat = try deriveFlatClaimGeometry(allocator, input.composition);
    defer flat.deinit();
    return init(allocator, .{
        .channel_salt = input.channel_salt,
        .pcs = input.pcs,
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
        .prover_input = input.prover_input,
    });
}

/// Serializes the independently derived Cairo public statement and flattened
/// claim geometry consumed by the pinned STWZCVE/1 Rust verifier adapter.
pub fn encodeCompactStatementV1(
    allocator: std.mem.Allocator,
    composition: *const composition_bundle.Bundle,
    prover_input: *const adapter.ProverInput,
) (Error || std.mem.Allocator.Error)![]u8 {
    var flat = try deriveFlatClaimGeometry(allocator, composition);
    defer flat.deinit();
    return encodeCompactStatementFromFlatClaimV1(allocator, .{
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
    }, prover_input);
}

pub const FlatClaimGeometryView = struct {
    component_enable_bits: []const bool,
    component_log_sizes: []const u32,
};

/// Serializes a runtime-generated claim without importing a composition
/// schedule or a target proof. The caller must resolve witness-fed component
/// logs before constructing this view.
pub fn encodeCompactStatementFromFlatClaimV1(
    allocator: std.mem.Allocator,
    flat: FlatClaimGeometryView,
    prover_input: *const adapter.ProverInput,
) (Error || std.mem.Allocator.Error)![]u8 {
    try validateFlatClaimGeometry(flat);
    const public = try derivePublicStatement(allocator, prover_input);
    defer allocator.free(public.public_claim);
    const segments = try extractPublicSegments(prover_input);
    const output = segments[0] orelse return Error.InvalidPublicSegmentContext;
    if (output.stop.value < output.start.value) return Error.InvalidOutputSegment;
    const output_count: usize = output.stop.value - output.start.value;
    const program_count: usize = public.program_len;

    const segment_bytes = std.math.mul(usize, adapter.N_PUBLIC_SEGMENTS, 5 * 4) catch
        return Error.ClaimLengthOverflow;
    const memory_count = std.math.add(usize, program_count, output_count) catch
        return Error.ClaimLengthOverflow;
    const memory_bytes = std.math.mul(
        usize,
        memory_count,
        compact_statement_memory_entry_words * 4,
    ) catch return Error.ClaimLengthOverflow;
    const enable_bytes = std.math.mul(usize, flat.component_enable_bits.len, 4) catch
        return Error.ClaimLengthOverflow;
    const log_bytes = std.math.mul(usize, flat.component_log_sizes.len, 4) catch
        return Error.ClaimLengthOverflow;
    var total_bytes = std.math.add(usize, compact_statement_header_bytes, segment_bytes) catch
        return Error.ClaimLengthOverflow;
    total_bytes = std.math.add(usize, total_bytes, memory_bytes) catch
        return Error.ClaimLengthOverflow;
    total_bytes = std.math.add(usize, total_bytes, enable_bytes) catch
        return Error.ClaimLengthOverflow;
    total_bytes = std.math.add(usize, total_bytes, log_bytes) catch
        return Error.ClaimLengthOverflow;

    const bytes = try allocator.alloc(u8, total_bytes);
    errdefer allocator.free(bytes);
    @memset(bytes, 0);
    @memcpy(bytes[0..compact_statement_magic.len], &compact_statement_magic);
    std.mem.writeInt(u16, bytes[8..10], compact_statement_version, .little);
    std.mem.writeInt(u16, bytes[10..12], compact_statement_header_bytes, .little);
    const initial = prover_input.state_transitions.initial_state;
    const final = prover_input.state_transitions.final_state;
    std.mem.writeInt(u32, bytes[16..20], initial.pc.toU32(), .little);
    std.mem.writeInt(u32, bytes[20..24], initial.ap.toU32(), .little);
    std.mem.writeInt(u32, bytes[24..28], initial.fp.toU32(), .little);
    std.mem.writeInt(u32, bytes[28..32], final.pc.toU32(), .little);
    std.mem.writeInt(u32, bytes[32..36], final.ap.toU32(), .little);
    std.mem.writeInt(u32, bytes[36..40], final.fp.toU32(), .little);
    const initial_ap = initial.ap.toU32();
    if (initial_ap < 2) return Error.InvalidProgramRange;
    const safe0 = try memoryEntryAt(prover_input.memory, initial_ap - 2);
    const safe1 = try memoryEntryAt(prover_input.memory, initial_ap - 1);
    if (!memoryValueEqualsU32(safe0.value, initial_ap) or !memoryValueIsZero(safe1.value))
        return Error.InvalidSafeCall;
    std.mem.writeInt(u32, bytes[40..44], safe0.id, .little);
    std.mem.writeInt(u32, bytes[44..48], safe1.id, .little);
    std.mem.writeInt(u32, bytes[48..52], @intCast(program_count), .little);
    std.mem.writeInt(u32, bytes[52..56], @intCast(output_count), .little);
    std.mem.writeInt(u32, bytes[56..60], @intCast(flat.component_enable_bits.len), .little);
    std.mem.writeInt(u32, bytes[60..64], @intCast(flat.component_log_sizes.len), .little);
    std.mem.writeInt(u32, bytes[64..68], adapter.N_PUBLIC_SEGMENTS, .little);
    std.mem.writeInt(u32, bytes[68..72], compact_statement_memory_entry_words, .little);

    var cursor: usize = compact_statement_header_bytes;
    for (segments) |segment| {
        if (segment) |range| {
            writeCompactStatementWord(bytes, &cursor, 1);
            writeCompactStatementWord(bytes, &cursor, range.start.id);
            writeCompactStatementWord(bytes, &cursor, range.start.value);
            writeCompactStatementWord(bytes, &cursor, range.stop.id);
            writeCompactStatementWord(bytes, &cursor, range.stop.value);
        } else {
            cursor += 5 * 4;
        }
    }
    const initial_pc = initial.pc.toU32();
    for (0..program_count) |offset| {
        const address = std.math.add(u32, initial_pc, @as(u32, @intCast(offset))) catch
            return Error.SegmentPointerOverflow;
        writeCompactMemoryEntry(bytes, &cursor, try memoryEntryAt(prover_input.memory, address));
    }
    for (0..output_count) |offset| {
        const address = std.math.add(u32, output.start.value, @as(u32, @intCast(offset))) catch
            return Error.SegmentPointerOverflow;
        writeCompactMemoryEntry(bytes, &cursor, try memoryEntryAt(prover_input.memory, address));
    }
    for (flat.component_enable_bits) |enabled| {
        writeCompactStatementWord(bytes, &cursor, @intFromBool(enabled));
    }
    for (flat.component_log_sizes) |log_size| {
        writeCompactStatementWord(bytes, &cursor, log_size);
    }
    std.debug.assert(cursor == bytes.len);
    return bytes;
}

fn writeCompactMemoryEntry(bytes: []u8, cursor: *usize, entry: MemoryEntry) void {
    writeCompactStatementWord(bytes, cursor, entry.id);
    for (memoryValueWords(entry.value)) |word| writeCompactStatementWord(bytes, cursor, word);
}

fn writeCompactStatementWord(bytes: []u8, cursor: *usize, word: u32) void {
    std.mem.writeInt(u32, bytes[cursor.*..][0..4], word, .little);
    cursor.* += 4;
}

/// Reconstructs Rust `CairoClaim::flatten_claim` order from the canonical
/// composition components. Every component contributes one flattened log;
/// `memory_id_to_big` is the only field with multiple claim instances.
pub fn deriveFlatClaimGeometry(
    allocator: std.mem.Allocator,
    bundle: *const composition_bundle.Bundle,
) (Error || std.mem.Allocator.Error)!OwnedFlatClaimGeometry {
    const components = try allocator.alloc(CanonicalClaimComponent, bundle.components.len);
    defer allocator.free(components);
    for (bundle.components, components) |component, *canonical| {
        canonical.* = .{
            .name = component.label,
            .instance = component.instance,
            .log_size = component.trace_log_size,
        };
    }
    return deriveFlatClaimGeometryFromCanonical(allocator, components);
}

const MemoryEntry = public_data.MemoryEntry;
const validateClaimWord = public_data.validateClaimWord;
const allocPadded = public_data.allocPadded;
const derivePublicStatement = public_data.derive;
const extractPublicSegments = public_data.extractPublicSegments;
const memoryEntryAt = public_data.memoryEntryAt;
const memoryValueWords = public_data.memoryValueWords;
const memoryValueEqualsU32 = public_data.memoryValueEqualsU32;
const memoryValueIsZero = public_data.memoryValueIsZero;

/// Derives ordinals 1, 2, and 10 through 16 in Rust verifier order.
pub fn init(
    allocator: std.mem.Allocator,
    input: StatementBootstrapInput,
) (Error || std.mem.Allocator.Error)!OwnedStatementBootstrap {
    try validateConfig(input.pcs);
    if (input.component_enable_bits.len > std.math.maxInt(u32)) return Error.ClaimLengthOverflow;
    for (input.component_log_sizes) |word| try validateClaimWord(word);

    const public = try derivePublicStatement(allocator, input.prover_input);
    defer allocator.free(public.public_claim);

    const ordinal_1 = try allocator.dupe(u32, &[_]u32{ input.channel_salt, 0, 0, 0 });
    errdefer allocator.free(ordinal_1);
    const ordinal_2 = try allocator.dupe(u32, &[_]u32{
        input.pcs.pow_bits,
        input.pcs.log_blowup_factor,
        input.pcs.n_queries,
        input.pcs.log_last_layer_degree_bound,
        input.pcs.fold_step,
        input.pcs.lifting_log_size orelse 0,
        0,
        0,
    });
    errdefer allocator.free(ordinal_2);
    const ordinal_10 = try allocator.dupe(u32, &[_]u32{
        @intCast(input.component_enable_bits.len), 0, 0, 0,
    });
    errdefer allocator.free(ordinal_10);
    const ordinal_11 = try allocPadded(allocator, input.component_enable_bits.len);
    errdefer allocator.free(ordinal_11);
    for (input.component_enable_bits, 0..) |enabled, index| ordinal_11[index] = @intFromBool(enabled);

    const ordinal_12 = try allocPadded(allocator, input.component_log_sizes.len);
    errdefer allocator.free(ordinal_12);
    @memcpy(ordinal_12[0..input.component_log_sizes.len], input.component_log_sizes);

    const ordinal_13 = try allocator.dupe(u32, &[_]u32{ public.program_len, 0, 0, 0 });
    errdefer allocator.free(ordinal_13);
    const ordinal_14 = try allocator.dupe(u32, public.public_claim);
    errdefer allocator.free(ordinal_14);
    const ordinal_15 = try allocator.dupe(u32, &public.output_root);
    errdefer allocator.free(ordinal_15);
    const ordinal_16 = try allocator.dupe(u32, &public.program_root);
    errdefer allocator.free(ordinal_16);

    return .{
        .allocator = allocator,
        .ordinal_1 = ordinal_1,
        .ordinal_2 = ordinal_2,
        .ordinal_10 = ordinal_10,
        .ordinal_11 = ordinal_11,
        .ordinal_12 = ordinal_12,
        .ordinal_13 = ordinal_13,
        .ordinal_14 = ordinal_14,
        .ordinal_15 = ordinal_15,
        .ordinal_16 = ordinal_16,
    };
}

fn validateConfig(config: PcsConfig) Error!void {
    inline for (.{
        config.pow_bits,
        config.log_blowup_factor,
        config.n_queries,
        config.log_last_layer_degree_bound,
        config.fold_step,
        config.lifting_log_size orelse 0,
    }) |word| try validateClaimWord(word);
}

fn validateFlatClaimGeometry(flat: FlatClaimGeometryView) Error!void {
    if (flat.component_enable_bits.len != claim_registry.enable_slot_count)
        return Error.InvalidClaimGeometry;
    var log_cursor: usize = 0;
    var memory_prefix_ended = false;
    for (claim_registry.enable_slots) |slot| {
        const enabled = flat.component_enable_bits[slot.enable_slot];
        if (slot.log_size_shape == .special_dynamic_prefix) {
            if (enabled and memory_prefix_ended) return Error.InvalidClaimGeometry;
            if (!enabled) memory_prefix_ended = true;
        }
        if (!enabled) continue;
        if (log_cursor >= flat.component_log_sizes.len) return Error.InvalidClaimGeometry;
        const log_size = flat.component_log_sizes[log_cursor];
        try validateClaimWord(log_size);
        if (slot.fixed_log_size) |fixed| {
            if (log_size != fixed) return Error.InvalidClaimGeometry;
        }
        log_cursor += 1;
    }
    if (log_cursor != flat.component_log_sizes.len) return Error.InvalidClaimGeometry;
}
