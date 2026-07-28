//! Pre-execution resolution of feed-dependent Cairo claim log sizes.
//!
//! `claim_generator.deriveFromProverInput` leaves every sub-component whose row
//! count is a *fan-out* of another component's real rows as
//! `LogSize.deferred`. Today those entries are resolved only by
//! `OwnedClaimGeometry.resolveFeedGeometry` — "the witness-to-statement
//! handoff" — which consumes `FeedGeometry` reports produced *during* witness
//! execution. That is what stops a claim-planned base-trace arena from being
//! laid out before execution (see `trace_arena`).
//!
//! This module closes that gap without executing anything. The authenticated
//! feed topology (`witness/feed_topology.zig`, digest-pinned) already states,
//! for every producer, how many instances of each target it feeds per row. A
//! deferred component's real row count is therefore
//!
//!     rows(D) = sum over active producers P of  instances(P -> D) * rows(P)
//!
//! and the root row counts are all present in `ExecutionResources`, i.e. in the
//! adapted prover input: opcode state counts and builtin segment lengths. The
//! claim's `paddedLog` is then applied exactly as `deriveFromResources` applies
//! it to a root, so the resulting log size is bit-identical to the one the
//! deferred path produces.
//!
//! **Structural admission, never a guess.** Resolution is refused — and the
//! caller falls back to today's deferred path — whenever any part of the closure
//! is not fully determined by the topology and the resources: an unknown
//! producer kind, a producer that is itself unresolved, a deferred component
//! with no active producer, or an arithmetic overflow. Nothing here is
//! conservative or approximate; either the closure is exact or it is refused.
//!
//! **Where the equality assertion lives.** The predicted value enters the claim
//! as `.known`, and `witness/live_graph.zig:validateClaimGeometry` already
//! compares every `.known` claim log size against the executed component's
//! padded row count and raises `ClaimGeometryMismatch` on disagreement. That
//! check runs per component, before any commitment exists, and it covers *every*
//! component rather than only the deferred ones — so it is strictly stronger
//! than the coverage the deferred path itself provides. A wrong prediction
//! cannot produce a proof.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const opcodes = @import("../adapter/opcodes.zig");
const claim_generator = @import("../claim_generator.zig");
const feed_topology = @import("../witness/feed_topology.zig");

pub const Error = error{
    /// The closure is not fully determined by the topology and the resources.
    /// Structural admission: the caller keeps the deferred path.
    UnresolvableFeedGeometry,
    /// A propagated row count left the representable range.
    FeedRowCountOverflow,
};

/// Row counts large enough to be corrupt rather than real. `paddedLog` refuses
/// anything above 2^31 anyway; this bound only keeps the propagation in u64.
const max_real_rows: u64 = 1 << 40;

pub const Outcome = struct {
    /// Number of `.deferred` entries the oracle resolved.
    resolved: usize,
    /// Number of `.deferred` entries present before resolution.
    deferred: usize,
};

/// Resolves every `.deferred` entry of `geometry` in place from `resources` and
/// the authenticated feed topology. On any refusal `geometry` is left exactly as
/// it was, so the caller can fall through to the deferred path.
pub fn resolveInPlace(
    allocator: std.mem.Allocator,
    geometry: *claim_generator.OwnedClaimGeometry,
    resources: claim_generator.ExecutionResources,
    topology: feed_topology.Loaded,
) (Error || std.mem.Allocator.Error)!Outcome {
    const deferred_before = geometry.deferredCount();
    if (deferred_before == 0) return .{ .resolved = 0, .deferred = 0 };

    const rows = try allocator.alloc(?u64, geometry.components.len);
    defer allocator.free(rows);
    @memset(rows, null);

    // Seed: every component whose real row count is a direct function of the
    // adapted prover input. Only opcode roots and builtin segments can produce
    // a deferred component (checked below), so only those need seeding.
    for (geometry.components, rows) |component, *slot| {
        if (component.log_size == .deferred) continue;
        slot.* = rootRealRows(component.name, resources);
    }

    // Fan-out propagation to a fixed point. Each pass resolves at least one
    // component or the closure is incomplete, so `components.len` passes bound
    // it. The topology fan-in is a DAG in practice; the bound does not assume
    // it.
    var remaining = deferred_before;
    var pass: usize = 0;
    while (remaining != 0) : (pass += 1) {
        if (pass > geometry.components.len) return Error.UnresolvableFeedGeometry;
        var progressed = false;
        for (geometry.components, 0..) |component, index| {
            if (component.log_size != .deferred or rows[index] != null) continue;
            const total = (try fanInRows(geometry, rows, topology, component)) orelse continue;
            rows[index] = total;
            progressed = true;
            remaining -= 1;
        }
        if (!progressed) return Error.UnresolvableFeedGeometry;
    }

    for (geometry.components, rows) |*component, slot| {
        if (component.log_size != .deferred) continue;
        const real = slot orelse return Error.UnresolvableFeedGeometry;
        component.log_size = .{ .known = try paddedLogChecked(real) };
    }
    return .{ .resolved = deferred_before, .deferred = deferred_before };
}

/// Sums `instances(P -> component) * rows(P)` over the producers `P` that are
/// active in this claim. Returns null when a contributing producer is not yet
/// resolved, and refuses when no active producer feeds the component at all.
fn fanInRows(
    geometry: *const claim_generator.OwnedClaimGeometry,
    rows: []const ?u64,
    topology: feed_topology.Loaded,
    component: claim_generator.ComponentGeometry,
) Error!?u64 {
    var total: u64 = 0;
    var contributors: usize = 0;
    for (topology.parsed.value.components) |producer| {
        var instances: u64 = 0;
        for (producer.feeds) |feed| {
            if (std.mem.eql(u8, feed.target, component.name)) instances += 1;
        }
        if (instances == 0) continue;
        const producer_index = indexOf(geometry, producer.producer) orelse continue;
        contributors += 1;
        const producer_rows = rows[producer_index] orelse return null;
        const contribution = std.math.mul(u64, producer_rows, instances) catch
            return Error.FeedRowCountOverflow;
        total = std.math.add(u64, total, contribution) catch
            return Error.FeedRowCountOverflow;
    }
    // A deferred component with no active producer would be a topology/claim
    // disagreement, and a zero-row one would be a padding decision this module
    // must not invent. Refuse both.
    if (contributors == 0 or total == 0) return Error.UnresolvableFeedGeometry;
    if (total > max_real_rows) return Error.FeedRowCountOverflow;
    return total;
}

/// Only single-instance components can participate: the deferred set's
/// producers are opcode roots and builtin segments, both of which the claim
/// carries at instance 0. `memory_id_to_big` is the one multi-instance field and
/// it feeds no deferred component.
fn indexOf(
    geometry: *const claim_generator.OwnedClaimGeometry,
    name: []const u8,
) ?usize {
    for (geometry.components, 0..) |component, index| {
        if (component.instance == 0 and std.mem.eql(u8, component.name, name))
            return index;
    }
    return null;
}

/// The real (pre-padding) row count of a component that is a direct function of
/// the adapted prover input. Returns null for anything else, which makes the
/// closure refuse rather than approximate.
fn rootRealRows(
    name: []const u8,
    resources: claim_generator.ExecutionResources,
) ?u64 {
    inline for (@typeInfo(opcodes.OpcodeTag).@"enum".fields) |field| {
        if (std.mem.eql(u8, name, field.name))
            return resources.opcode_counts[field.value];
    }
    const segments = resources.builtin_segments;
    const builtins = [_]struct { name: []const u8, segment: ?adapter.MemorySegmentAddresses, cells: u64 }{
        .{ .name = "add_mod_builtin", .segment = segments.add_mod_builtin, .cells = 7 },
        .{ .name = "bitwise_builtin", .segment = segments.bitwise_builtin, .cells = 5 },
        .{ .name = "mul_mod_builtin", .segment = segments.mul_mod_builtin, .cells = 7 },
        .{ .name = "poseidon_builtin", .segment = segments.poseidon_builtin, .cells = 6 },
        .{ .name = "range_check96_builtin", .segment = segments.range_check96_builtin, .cells = 1 },
        .{ .name = "range_check_builtin", .segment = segments.range_check_builtin, .cells = 1 },
        .{ .name = "ec_op_builtin", .segment = segments.ec_op_builtin, .cells = 7 },
        .{ .name = "pedersen_builtin", .segment = segments.pedersen_builtin, .cells = 3 },
        .{ .name = "pedersen_builtin_narrow_windows", .segment = segments.pedersen_builtin, .cells = 3 },
    };
    for (builtins) |builtin| {
        if (!std.mem.eql(u8, name, builtin.name)) continue;
        const segment = builtin.segment orelse return null;
        if (segment.stop_ptr < segment.begin_addr) return null;
        const length = segment.stop_ptr - segment.begin_addr;
        if (length == 0 or length % builtin.cells != 0) return null;
        return length / builtin.cells;
    }
    return null;
}

fn paddedLogChecked(real_rows: u64) Error!u32 {
    const padded = @max(real_rows, @as(u64, 1) << claim_generator.simd_log_lanes);
    const log_size = std.math.log2_int_ceil(u64, padded);
    if (log_size > 31) return Error.FeedRowCountOverflow;
    return @intCast(log_size);
}
