//! Typed AIR for block-v2 initial RW first-touch values.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../air/lang/definition.zig");
const effects = @import("../recursion/air/relation_effect.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const bus = @import("block_memory_relation_v2.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const Layout = struct {
    pub const value = 0;
    pub const address = 4;
    pub const circuit = 8;
    pub const wire = 9;
    pub const active = 10;
    pub const initial_emit = 11;
    pub const len = 12;
};
pub const Row = [Layout.len]M;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 8;
pub const LOGICAL_INPUT_COUNT = Layout.len;
pub const DIRECT_CONSTRAINT_COUNT = 6;
pub const RELATION_EVENT_COUNT = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const MAX_FIRST_TOUCH_KEYS_PER_CHUNK: usize = 4096;
pub const TRANSCRIPT_TAG: u32 = 0x42324952; // B2IR
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "da47f47d6205f0d3defd0d5f17ac37fb762add1aa83e564beeeeb235f05089e0") catch @compileError("invalid RW initial AIR digest");
    break :blk out;
};

pub const Claim = struct {
    roster_digest: [32]u8,
    row_count: u32,
    log_size: u32,
    initial_sum: Q,

    /// The roster digest belongs in the sealed block statement before any
    /// relation draw; the interaction sum is mixed before the third PCS tree.
    pub fn mixInteraction(self: Claim, channel: anytype) void {
        channel.mixU32s(&.{ TRANSCRIPT_TAG, 2, self.row_count, self.log_size });
        for (self.initial_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
};

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: [8][]M,
    storage: []M,
    claim: Claim,
    pub fn deinit(self: *Interaction) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

pub const Point = struct {
    active: Q,
    initial_emit: Q,
    first: Q,
    domain_last: Q,
    tuple: [bus.INITIAL_ARITY]Q,
    term: Q,
    prefix: Q,
    previous_prefix: Q,
};

/// Polynomial identities over PCS-opened fixed/main/interaction cells.
/// The caller must also prove the typed direct AIR and byte/wire effects.
pub fn interactionConstraints(challenge: *const bus.Challenges, point: Point, claim: Claim) ![3]Q {
    if (claim.log_size == 0 or claim.log_size > 30 or claim.row_count == 0 or
        claim.row_count > @as(u32, 1) << @intCast(claim.log_size)) return error.InvalidInitialRwClaim;
    const one = Q.one();
    const den = point.initial_emit.mul(challenge.initial.combineSecure(point.tuple)).add(one.sub(point.initial_emit));
    const fraction = den.mul(point.term).sub(point.initial_emit);
    const shifted = try claim.initial_sum.divM31(M.fromCanonical(@as(u32, 1) << @intCast(claim.log_size)));
    const recurrence = point.prefix.sub(one.sub(point.first).mul(point.previous_prefix)).sub(point.term).add(shifted);
    return .{ fraction, recurrence, point.domain_last.mul(point.prefix) };
}

pub const Definition = struct {
    arena: lang.ir.Arena,
    inputs: [Layout.len]Id,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidInitialRwAir;
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST)) return error.InvalidInitialRwAir;
    }
};

pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
    var d = try buildRaw(a);
    defer d.deinit();
    return (try lang.digest.computeIdentity(&d.arena)).bytes;
}

/// The two universal byte lookups and the wire source are genuine typed
/// effects. The block-specific 9-field initial bus is evaluated separately
/// because its v2 challenge is intentionally absent from the frozen registry.
pub fn build(a: std.mem.Allocator) !Definition {
    var result = try buildRaw(a);
    errdefer result.deinit();
    try result.validate();
    return result;
}
fn buildRaw(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [Layout.len]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "block_rw_initial.input_{d}", .{i}), if (i < 8) .byte else if (i == Layout.active or i == Layout.initial_emit) .selector else .felt, span);
    }
    const one = try arena.constantField(1, span);
    _ = try arena.assertZero("block_rw_initial.active_bit", try arena.mul(ids[Layout.active], try arena.sub(ids[Layout.active], one, span), span), null, .semantic, span);
    _ = try arena.assertZero("block_rw_initial.initial_emit_bit", try arena.mul(ids[Layout.initial_emit], try arena.sub(ids[Layout.initial_emit], one, span), span), null, .semantic, span);
    const not_path_active = try arena.sub(one, ids[Layout.active], span);
    for (0..4) |byte| {
        var name: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&name, "block_rw_initial.zero_query_byte_{d}", .{byte}), try arena.mul(not_path_active, ids[Layout.value + byte], span), null, .semantic, span);
    }
    const event_ids = try effects.appendGroup(3, &arena, .{
        .{ .domain = .range_check_8_8, .role = .request, .values = ids[0..2], .weight = ids[Layout.active] },
        .{ .domain = .range_check_8_8, .role = .request, .values = ids[2..4], .weight = ids[Layout.active] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[Layout.circuit], ids[Layout.wire] } ++ ids[0..4].*), .weight = ids[Layout.active] },
    }, span);
    return .{ .arena = arena, .inputs = ids, .events = event_ids };
}

/// Selected addresses must be sorted and unique. Publishing this list before
/// challenge draw pins both the fixed AIR rows and the sparse path topology.
pub fn tupleFromRow(row: Row) bus.InitialTuple {
    var tuple: bus.InitialTuple = @splat(M.zero());
    tuple[0] = M.one();
    @memcpy(tuple[1..5], row[Layout.address..][0..4]);
    @memcpy(tuple[5..9], row[Layout.value..][0..4]);
    return tuple;
}

/// The verifier recomputes all fixed columns from this public, sealed roster.
/// Value columns remain private PCS witness; an initial-bus quotient must read
/// both the fixed address and private value from its authenticated opening.
pub fn fixedRow(address: u32, caller_base: u32, index: u32) !Row {
    return fixedRowWithSelectors(address, caller_base, index, true, true);
}
pub fn fixedRowWithSelectors(address: u32, caller_base: u32, index: u32, path_active: bool, initial_emit: bool) !Row {
    if (address & 3 != 0 or address >= tree.ADDRESS_LIMIT) return error.InvalidInitialRwAddress;
    const circuit = try std.math.add(u32, caller_base, index);
    if (circuit >= core.fields.m31.Modulus) return error.InitialRwCallerOverflow;
    var row: Row = @splat(M.zero());
    for (0..4) |j| row[Layout.address + j] = M.fromCanonical(@as(u8, @truncate(address >> @intCast(j * 8))));
    row[Layout.circuit] = M.fromCanonical(circuit);
    row[Layout.active] = M.fromCanonical(@intFromBool(path_active));
    row[Layout.initial_emit] = M.fromCanonical(@intFromBool(initial_emit));
    return row;
}
