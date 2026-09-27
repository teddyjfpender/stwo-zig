//! Derive ordinary-to-continuation edits from admitted execution public data.
//! Callers must also authenticate the execution proof and bind the converted
//! endpoint to the span claim. Snapshot role flags are never an authority here.
const std = @import("std");
const public = @import("../../air/public_data.zig");
const commitment = @import("../../prover/blake3_commitment_plan.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const chain = @import("blake3_memory_update_chain.zig");
pub const Side = @import("blake3_memory_snapshot.zig").Side;
const Direction = @import("blake3_memory_boundary.zig").Direction;
pub const Prepared = struct {
    plan: chain.Plan,
    rows: chain.Prepared,
    pub fn deinit(self: *Prepared) void {
        self.rows.deinit();
        self.plan.deinit();
        self.* = undefined;
    }
};
/// Build a conversion against both admitted ordinary and caller-supplied full
/// memory roots. Neither a snapshot root nor a newly computed plan ID can
/// substitute for those endpoints. The caller authenticates the full root as
/// part of its span admission before this witness is accepted in a parent.
pub fn prepare(a: std.mem.Allocator, side: Side, data: *const public.Blake3PublicData, admission: commitment.Admission, initial: []const tree.Leaf, full_root: tree.Digest, namespace: u32, source_circuit: u32) !Prepared {
    const allowed = try edits(a, side, data, admission);
    defer a.free(allowed);
    var plan = try chain.planWitness(a, namespace, source_circuit, allowed, initial);
    errdefer plan.deinit();
    const ordinary_root = admission.plan.roots[if (side == .entry) @as(usize, 1) else 2];
    const rows = try chain.prepare(a, &plan, try plan.identity(), ordinary_root, full_root, initial);
    return .{ .plan = plan, .rows = rows };
}
/// Each excluded public word is restored from zero, including zero-valued words.
/// Every byte limb remains bound; no partial-word custody is admitted.
pub fn edits(a: std.mem.Allocator, side: Side, data: *const public.Blake3PublicData, admission: commitment.Admission) ![]chain.Edit {
    try admission.validatePublic(data);
    var result: std.ArrayList(chain.Edit) = .empty;
    errdefer result.deinit(a);
    for (data.io_entries.input_words, 0..) |value, index| {
        const address = try data.io_entries.inputWordAddress(index);
        if (hasBoundary(admission.plan, .initial, address)) return error.ConflictingPublicMemoryCustody;
        if (side == .entry or !hasBoundary(admission.plan, .final, address)) try appendWord(a, &result, address, value);
    }
    if (side == .exit) {
        for (data.io_entries.output_words) |word| {
            if (hasBoundary(admission.plan, .final, word.addr)) return error.ConflictingPublicMemoryCustody;
            try appendWord(a, &result, word.addr, word.value);
        }
        if (data.completion) |completion| if (completion.kind == .halt_flag) {
            if (hasBoundary(admission.plan, .final, completion.address)) return error.ConflictingPublicMemoryCustody;
            try appendWord(a, &result, completion.address, completion.value);
        };
    }
    std.mem.sort(chain.Edit, result.items, {}, struct {
        fn less(_: void, lhs: chain.Edit, rhs: chain.Edit) bool {
            return lhs.address < rhs.address;
        }
    }.less);
    for (result.items, 0..) |edit, index| {
        if (index > 0 and result.items[index - 1].address == edit.address) return error.ConflictingPublicMemoryCustody;
    }
    return result.toOwnedSlice(a);
}
/// Check an already constructed chain before it can become parent fixed data.
/// The final full-memory root still needs authentication by the span protocol.
pub fn admit(plan: *const chain.Plan, side: Side, data: *const public.Blake3PublicData, admission: commitment.Admission, a: std.mem.Allocator) !void {
    try plan.validate();
    const expected = try edits(a, side, data, admission);
    defer a.free(expected);
    const root = admission.plan.roots[if (side == .entry) @as(usize, 1) else 2];
    if (!std.meta.eql(plan.roots[0], root) or plan.edits.len != expected.len) return error.UntrustedMemoryCustody;
    for (plan.edits, expected) |actual, wanted| if (!std.meta.eql(actual, wanted)) return error.UntrustedMemoryCustody;
}
fn hasBoundary(plan: *const commitment.Plan, direction: Direction, address: u32) bool {
    for (plan.memories) |item| if (item.direction == direction and item.address == address) return true;
    return false;
}
fn appendWord(a: std.mem.Allocator, result: *std.ArrayList(chain.Edit), address: u32, value: u32) !void {
    if (address & 3 != 0 or address >= tree.ADDRESS_LIMIT) return error.InvalidPublicMemoryAddress;
    try result.append(a, .{ .address = try tree.memoryIndex(address), .before = 0, .after = value });
}
