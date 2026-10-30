//! Byte-only fresh receiver for the bounded many-cohort closed-window root.
//! No original proofs, producer keys, proof captures or successful receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Local = @import("block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const Bridge = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("block_v8_compact_ram_recursive_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_local_scope_v1.zig");
const Metadata = @import("../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Window = @import("../prover/block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Source = @import("block_v8_endpoint_join_source_v1.zig");
pub const External = @import("../prover/block_v8_endpoint_local_bundle_v1.zig").External;
pub const Claims = struct { locals: []Local.Ledger.Claims, bridge: []const Q, global: Global.Original.Claims };
/// Only metadata, physical claims and a nominated MAIN commitment. No child
/// proof, capture, producer key or successful receipt is accepted here.
pub const Leaf = struct { global_g_repartition: bool = false, main_root: [32]u8, physical_claims: []const u8, local_metadata: []const []const u8, global_roots: [4][32]u8, cohort_policy: Window.CohortPolicy, selected_addresses: []const u32 };
pub const Verified = @import("blake3_native_parent_verifier.zig").Verified;
/// Independently admitted original statements before any NativeParent rows.
/// The owned arena keeps decoded physical claims alive; each statement owns
/// its own scope. ELF and checkpoint buffers remain immutable caller borrows.
pub const MetadataOwned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    locals: []*Local.Statement.Owned,
    bridge: *Bridge.Statement.Owned,
    global: *Global.Statement.Owned,
    admissions: []Source.Admission,
    extra: [264]Q,
    pub fn deinit(self: *@This()) void {
        self.global.deinit();
        self.bridge.deinit();
        for (self.locals) |local| local.deinit();
        self.allocator.free(self.locals);
        self.allocator.free(self.admissions);
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn admitLeafMetadata(a: std.mem.Allocator, external: External, input: Leaf) !MetadataOwned {
    const n = input.local_metadata.len;
    if (n == 0 or n > 62 or n != input.cohort_policy.cohort_count or input.physical_claims.len > 8 << 20 or !std.meta.eql(external.config, @import("blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedEndpointJoinReceiving;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = input.physical_claims };
    var remaining: usize = 1 << 20;
    const claims = try @import("../prover/block_v7_union_claim_wire_v1.zig").decode(Claims, arena.allocator(), &cursor, &remaining);
    if (cursor.position != input.physical_claims.len or claims.locals.len != n or claims.bridge.len != n) return error.NonCanonicalEndpointJoinClaims;
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, input.cohort_policy, input.selected_addresses, external.boundary, .{});
    defer window.deinit();
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = @intCast(n), .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
    const statements = try a.alloc(*Local.Statement.Owned, n);
    errdefer a.free(statements);
    var count: usize = 0;
    errdefer for (statements[0..count]) |statement| statement.deinit();
    const pins = try a.alloc(BridgeScope.Source, n);
    defer a.free(pins);
    const admitted = try a.alloc(Source.Admission, n + 2);
    errdefer a.free(admitted);
    var events: u32 = 0;
    for (input.local_metadata, 0..) |bytes, i| {
        statements[i] = try Metadata.decode(a, bytes, trusted, .{});
        count += 1;
        const local = try Scope.Owned.init(a, trusted, statements[i].input, .{});
        defer local.deinit();
        const source = local.source();
        pins[i] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
        events = try std.math.add(u32, events, source.endpoint_count);
        admitted[i] = .{ .local = .{ .statement = statements[i], .claims = claims.locals[i] } };
    }
    const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = events };
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(input.global_roots), .batch_first = 0, .batch_count = @intCast(n) });
    errdefer bridge.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = input.global_roots });
    errdefer global.deinit();
    admitted[n] = .{ .bridge = .{ .statement = bridge, .claims = claims.bridge } };
    admitted[n + 1] = .{ .global = .{ .statement = global, .claims = claims.global } };
    return .{ .allocator = a, .arena = arena, .locals = statements, .bridge = bridge, .global = global, .admissions = admitted, .extra = boundaryBytes(&window) };
}
pub fn deriveLeaf(a: std.mem.Allocator, external: External, input: Leaf) !*@import("block_v8_window_root_profile_v1.zig").Owned {
    var metadata = try admitLeafMetadata(a, external, input);
    defer metadata.deinit();
    return @import("block_v8_window_root_profile_v1.zig").Owned.deriveJoin(a, metadata.admissions, &metadata.extra, input.main_root, .{ .global_g_repartition = input.global_g_repartition });
}
pub fn boundaryBytes(window: *const Window.Owned) [264]Q {
    var extra: [264]Q = undefined;
    var words: [66]u32 = undefined;
    words[0] = window.boundary.initial_cpu.pc;
    @memcpy(words[1..33], &window.boundary.initial_cpu.regs);
    words[33] = window.boundary.final_cpu.pc;
    @memcpy(words[34..66], &window.boundary.final_cpu.regs);
    for (words, 0..) |word, i| for (0..4) |byte| {
        extra[4 * i + byte] = Q.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255));
    };
    return extra;
}

/// An unpadded bounded hierarchy. Every leaf independently admits ELF/snapshot
/// metadata; each internal node recompiles the same exact recursive fold.
pub const Tree = union(enum) {
    leaf: struct { external: External, input: Leaf },
    mixed_leaf: struct { external: External, input: @import("block_v8_endpoint_mixed_join_receiver_v1.zig").Input, main_root: [32]u8, global_g_repartition: bool = false },
    branch: struct { children: []const Tree, main_root: [32]u8 },
    pub fn derive(v: Tree, a: std.mem.Allocator) anyerror!*@import("block_v8_window_root_profile_v1.zig").Owned {
        var remaining: usize = 4096;
        return v.deriveAt(a, 0, &remaining);
    }
    fn deriveAt(v: Tree, a: std.mem.Allocator, depth: usize, remaining: *usize) anyerror!*@import("block_v8_window_root_profile_v1.zig").Owned {
        if (depth > 16 or remaining.* == 0) return error.B8WindowRootResourceLimit;
        remaining.* -= 1;
        switch (v) {
            .leaf => |leaf| return deriveLeaf(a, leaf.external, leaf.input),
            .mixed_leaf => |leaf| {
                var metadata = try @import("block_v8_endpoint_mixed_join_receiver_v1.zig").admitMetadata(a, leaf.external, leaf.input);
                defer metadata.deinit();
                return @import("block_v8_window_root_profile_v1.zig").Owned.deriveJoin(a, &metadata.admissions, &metadata.extra, leaf.main_root, .{ .global_g_repartition = leaf.global_g_repartition });
            },
            .branch => |branch| {
                if (branch.children.len < 2 or branch.children.len > 4) return error.InvalidB8WindowFanIn;
                var children: [4]*@import("block_v8_window_root_profile_v1.zig").Owned = undefined;
                var count: usize = 0;
                defer for (children[0..count]) |child| child.deinit();
                for (branch.children, 0..) |child, i| {
                    children[i] = try child.deriveAt(a, depth + 1, remaining);
                    count += 1;
                }
                return @import("block_v8_window_root_profile_v1.zig").Owned.deriveFold(a, children[0..count], branch.main_root);
            },
        }
    }
};
pub fn verify(a: std.mem.Allocator, root: []const u8, metadata: Tree, expected: @import("block_v8_window_root_statement_v1.zig").WindowSpan) !Verified {
    if (root.len == 0 or root.len > 64 << 20) return error.B8WindowRootResourceLimit;
    const profile = try metadata.derive(a);
    defer profile.deinit();
    if (!std.meta.eql(profile.span, expected)) return error.UntrustedB8FoldCoverage;
    return verifyProfile(a, root, profile);
}
fn verifyProfile(a: std.mem.Allocator, root: []const u8, profile: *const @import("block_v8_window_root_profile_v1.zig").Owned) !Verified {
    if (root.len == 0 or root.len > 64 << 20) return error.B8WindowRootResourceLimit;
    var decoded = try @import("blake3_execution_parent_proof.zig").codec.decode(a, root, &profile.admission);
    var result = try @import("blake3_execution_parent_proof.zig").verify(&decoded, &profile.admission);
    errdefer result.deinit();
    const capture = @import("block_v8_window_root_profile_v1.zig").Capture.borrow(&result);
    try profile.requireCapture(&capture);
    return result;
}

/// Full-execution receiving adds independently derived input initialization and
/// terminal output policy authority. The policies must already be inside the
/// child source keys/Compact boundary AIR, as nominated by the typed tree.
pub fn verifyFull(a: std.mem.Allocator, root: []const u8, metadata: Tree, boundary: *const @import("../prover/block_v8_full_boundary_policy_v1.zig").Owned) !Verified {
    try requireBoundarySelection(metadata, boundary);
    const profile = try metadata.derive(a);
    defer profile.deinit();
    const span = profile.span;
    if (span.first_cycle != 1 or span.cycles != boundary.terminal_policy.policy.final_cycle or !std.meta.eql(span.elf_sha256, boundary.elf_sha256) or !std.meta.eql(span.config, boundary.config) or !std.meta.eql(span.incoming_snapshot_id, boundary.initial_policy.snapshot_id) or !std.meta.eql(span.initial_cpu, boundary.initial_policy.cpu) or span.initial_policy_id == null or span.terminal_policy_id == null or !std.meta.eql(span.initial_policy_id.?, boundary.initial_policy.policy_id) or !std.meta.eql(span.terminal_policy_id.?, boundary.terminal_policy.policy_id)) return error.UntrustedB8FullExecutionBoundary;
    return verifyProfile(a, root, profile);
}

fn requireBoundarySelection(metadata: Tree, boundary: *const @import("../prover/block_v8_full_boundary_policy_v1.zig").Owned) anyerror!void {
    switch (metadata) {
        inline .leaf, .mixed_leaf => |leaf| {
            const selected = try boundary.windowOptions(leaf.external.trusted.window.skip_cycles, leaf.external.trusted.window.cycles);
            if (!std.meta.eql(selected, leaf.external.boundary)) return error.UntrustedB8FullExecutionBoundary;
        },
        .branch => |branch| for (branch.children) |child| try requireBoundarySelection(child, boundary),
    }
}
