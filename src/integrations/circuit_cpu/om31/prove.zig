//! Independent native-OM31 circuit prover and receiver. Legacy V2 circuit proof
//! codecs, roots and registries are not accepted or silently converted here.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
const W = @import("witness.zig");
const C = @import("component.zig").Component;
const O = P.O;
const Q = P.Q;
const List = circuit.common.component_list;
const Preprocessed = circuit.common.preprocessed.PreprocessedCircuit;
const Col = prover.pcs.ColumnEvaluation;
const Components = prover.air.component_prover.ForField(O);
const CoreAir = core.air.components.ForField(O);
pub const Capture = core.pcs.ForField(O).verifier.VerifiedProofCapture(P.H);
/// OM31 widens challenges, not the characteristic of M31 multiplicities.
/// The independently constructed circuit topology bounds every positive
/// gather by a unit request; table/provider multiplicities count those uses.
pub fn validateGatherMass(logs: List.PerComponent(u32), n_outputs: usize) !u64 {
    var mass = std.math.add(u64, @intCast(n_outputs), 1) catch return error.Om31CircuitCharacteristicBound;
    for (std.enums.values(List.ComponentList)[0..5]) |kind| {
        const log = logs.get(kind);
        if (log >= 31) return error.Om31CircuitCharacteristicBound;
        const rows = @as(u64, 1) << @intCast(log);
        const terms = circuit.witness.trace.RawLookupRows.count(kind);
        mass = std.math.add(u64, mass, rows * terms) catch return error.Om31CircuitCharacteristicBound;
    }
    if (mass >= core.fields.m31.Modulus) return error.Om31CircuitCharacteristicBound;
    return mass;
}
/// External proof material never selects a replacement AIR recording.
pub fn parsePinnedAir(a: std.mem.Allocator, bytes: []const u8) !Air.Bundle {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, Air.bundle_sha256)) return error.InvalidOm31CircuitAirAuthority;
    return Air.parse(a, bytes);
}
/// Fail before constructing a recursion graph if its pinned recording is
/// missing or unreadable from the current working directory.
pub fn requirePinnedAir(a: std.mem.Allocator) !void {
    const bytes = std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20) catch |err| {
        std.log.err("cannot read pinned circuit AIR at {s}: {s}", .{ Air.bundle_path, @errorName(err) });
        return err;
    };
    defer a.free(bytes);
    var template = try parsePinnedAir(a, bytes);
    defer template.deinit();
}

pub const Authority = struct {
    allocator: std.mem.Allocator,
    pp: *const Preprocessed,
    layout: circuit.common.preprocessed.ColumnLayout,
    logs: List.PerComponent(u32),
    fixed_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32,
    bound: Air.Bundle,
    fixed: ?P.Scheme.CommittedTree,
    fixed_root: P.H.Hash,
    retired: bool = false,
    device_fixed: bool = false,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, pp: *const Preprocessed) !Authority {
        return initImpl(a, pp, null);
    }
    /// PROVER ONLY: root must come from the caller's live trusted device
    /// precommit of this exact PP. Independent receivers always use init().
    pub fn initForDeviceProver(a: std.mem.Allocator, pp: *const Preprocessed, root: P.H.Hash) !Authority {
        return initImpl(a, pp, root);
    }
    /// PROVER ONLY, device-free: every root-independent part of
    /// initForDeviceProver (pinned AIR parse, layout, bind). `finish` with the
    /// trusted device root yields exactly the initForDeviceProver authority.
    pub const DevicePrepared = struct {
        allocator: std.mem.Allocator,
        pp: *const Preprocessed,
        layout: circuit.common.preprocessed.ColumnLayout,
        logs: List.PerComponent(u32),
        fixed_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32,
        bound: ?Air.Bundle,
        pub fn deinit(self: *DevicePrepared) void {
            if (self.bound) |*bound| bound.deinit();
            self.bound = null;
        }
        /// Consumes the bound AIR on success; the caller still deinit()s.
        pub fn finish(self: *DevicePrepared, pp: *const Preprocessed, root: P.H.Hash) !Authority {
            if (pp != self.pp) return error.InvalidOm31CircuitPreparedAuthority;
            const bound = self.bound orelse return error.InvalidOm31CircuitPreparedAuthority;
            self.bound = null;
            return .{ .allocator = self.allocator, .pp = pp, .layout = self.layout, .logs = self.logs, .fixed_logs = self.fixed_logs, .bound = bound, .fixed = null, .fixed_root = root, .device_fixed = true, .identity = identityOf(root, self.logs, pp.n_outputs) };
        }
    };
    pub fn prepareForDeviceProver(a: std.mem.Allocator, pp: *const Preprocessed) !DevicePrepared {
        const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
        defer a.free(bytes);
        var template = try parsePinnedAir(a, bytes);
        defer template.deinit();
        const layout = pp.layout();
        const logs = try List.circuitComponentLogSizes(&layout);
        _ = try validateGatherMass(logs, pp.n_outputs);
        const bound = try Air.bind(a, &template, logs, &layout);
        var fixed_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
        for (pp.columns, &fixed_logs) |column, *log| log.* = column.logSize();
        return .{ .allocator = a, .pp = pp, .layout = layout, .logs = logs, .fixed_logs = fixed_logs, .bound = bound };
    }
    /// RECEIVER ONLY (stream rootverify, M5 root-only path): a verifier-only
    /// authority rebuilt from a compact, receiver-derived verifier key
    /// (column layout, output count, FIXED root). The layout fixes the
    /// component row logs and FIXED column logs; the bound AIR is the pinned
    /// bundle bound to them, exactly as in init(). The identity is RECOMPUTED
    /// here from (root, logs, n_outputs), never taken from the key, so a key
    /// whose recorded identity disagrees is rejected by the caller. The result
    /// is born retired: it can verify, never prove. `stub` must outlive the
    /// authority and carry `n_outputs` (its column values are never read).
    pub fn initVerifier(a: std.mem.Allocator, stub: *const Preprocessed, layout: circuit.common.preprocessed.ColumnLayout, root: P.H.Hash) !Authority {
        const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
        defer a.free(bytes);
        var template = try parsePinnedAir(a, bytes);
        defer template.deinit();
        const logs = try List.circuitComponentLogSizes(&layout);
        _ = try validateGatherMass(logs, stub.n_outputs);
        const bound = try Air.bind(a, &template, logs, &layout);
        var fixed_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
        for (layout.entries, &fixed_logs) |entry, *log| log.* = entry.log_size;
        return .{ .allocator = a, .pp = stub, .layout = layout, .logs = logs, .fixed_logs = fixed_logs, .bound = bound, .fixed = null, .fixed_root = root, .retired = true, .identity = identityOf(root, logs, stub.n_outputs) };
    }
    fn identityOf(root: P.H.Hash, logs: List.PerComponent(u32), n_outputs: usize) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(P.domainName());
        hash.update(Air.bundle_sha256);
        hash.update(&root);
        var word: [4]u8 = undefined;
        for (logs.toArray()) |log| {
            std.mem.writeInt(u32, &word, log, .little);
            hash.update(&word);
        }
        std.mem.writeInt(u32, &word, @intCast(n_outputs), .little);
        hash.update(&word);
        return hash.finalResult();
    }
    fn initImpl(a: std.mem.Allocator, pp: *const Preprocessed, device_root: ?P.H.Hash) !Authority {
        const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
        defer a.free(bytes);
        var template = try parsePinnedAir(a, bytes);
        defer template.deinit();
        const layout = pp.layout();
        const logs = try List.circuitComponentLogSizes(&layout);
        _ = try validateGatherMass(logs, pp.n_outputs);
        var bound = try Air.bind(a, &template, logs, &layout);
        errdefer bound.deinit();
        var fixed: ?P.Scheme.CommittedTree = null;
        errdefer if (fixed) |*tree| tree.deinit(a);
        var fixed_logs: [circuit.common.preprocessed.N_PREPROCESSED_COLUMNS]u32 = undefined;
        for (pp.columns, &fixed_logs) |column, *log| log.* = column.logSize();
        const root = if (device_root) |root| root else blk: {
            var scheme = try P.Engine.init(a, try P.targetConfig());
            defer scheme.deinit(a);
            var channel = P.Channel.init();
            const columns = try a.alloc(Col, pp.columns.len);
            defer a.free(columns);
            for (columns, pp.columns, fixed_logs) |*out, column, log| out.* = .{ .log_size = log, .values = column.values };
            try scheme.commit(a, columns, &channel);
            fixed = scheme.trees.orderedRemove(0);
            try fixed.?.share(a);
            break :blk fixed.?.root();
        };
        return .{ .allocator = a, .pp = pp, .layout = layout, .logs = logs, .fixed_logs = fixed_logs, .bound = bound, .fixed = fixed, .fixed_root = root, .device_fixed = device_root != null, .identity = identityOf(root, logs, pp.n_outputs) };
    }
    pub fn deinit(self: *Authority) void {
        if (self.fixed) |*fixed| fixed.deinit(self.allocator);
        self.bound.deinit();
        self.* = undefined;
    }
    pub fn fixedRoot(self: *const Authority) P.H.Hash {
        return self.fixed_root;
    }
    pub fn requireProverData(self: *const Authority) !void {
        if (self.retired or (self.fixed == null and !self.device_fixed)) return error.Om31CircuitProverDataRetired;
    }
    pub fn retainFixed(self: *const Authority) !P.Scheme.CommittedTree {
        try self.requireProverData();
        return (self.fixed orelse return error.Om31CircuitDeviceFixedRequiresDeviceProver).retainShared();
    }
    /// Keep the original verifier root, geometry and bound AIR, while releasing
    /// FIXED polynomial buffers no longer needed after a completed proof.
    /// The caller separately owns and may retire its PP column values.
    pub fn retireProverData(self: *Authority) void {
        if (self.fixed) |*fixed| fixed.deinit(self.allocator);
        self.fixed = null;
        self.retired = true;
    }
    pub fn treeLogs(self: *const Authority, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree == 0) return a.dupe(u32, &self.fixed_logs);
        if (tree > 2) return error.InvalidOm31CircuitTree;
        const widths = if (tree == 1) circuit.witness.trace.traceWidths() else circuit.witness.trace.interactionWidths();
        var count: usize = 0;
        for (widths) |width| count += if (tree == 2) width * 2 else width;
        const out = try a.alloc(u32, count);
        var at: usize = 0;
        for (widths, self.logs.toArray()) |width, log| {
            const n = if (tree == 2) width * 2 else width;
            @memset(out[at..][0..n], log);
            at += n;
        }
        return out;
    }
};
pub const Produced = struct {
    allocator: std.mem.Allocator,
    outputs: []Q,
    claims: W.Claims,
    proof: P.Engine.ExtendedProof,
    pub fn deinit(self: *Produced) void {
        self.proof.deinit(self.allocator);
        self.allocator.free(self.outputs);
        self.* = undefined;
    }
};
pub fn begin(a: std.mem.Allocator, key: *const Authority, outputs: []const Q) !P.Channel {
    if (outputs.len != key.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
    var channel = P.Channel.init();
    (try P.targetConfig()).mixInto(&channel);
    P.mixProfile(&channel);
    const words = try a.alloc(u32, 8 + 1 + 4 * outputs.len);
    defer a.free(words);
    for (0..8) |i| words[i] = std.mem.readInt(u32, key.identity[4 * i ..][0..4], .little);
    words[8] = @intCast(outputs.len);
    for (outputs, 0..) |q, i| {
        for (q.toM31Array(), 0..) |m, j| words[9 + 4 * i + j] = m.v;
    }
    channel.mixU32s(words);
    return channel;
}
pub fn draw(channel: *P.Channel) struct { z: O, alpha: O } {
    return .{ .z = channel.drawSecureFelt(), .alpha = channel.drawSecureFelt() };
}
pub fn bind(a: std.mem.Allocator, key: *const Authority, z: O, alpha: O, claims: W.Claims) ![]C {
    const out = try a.alloc(C, List.N_COMPONENTS);
    errdefer a.free(out);
    for (out, key.bound.components, claims.toArray()) |*component, *captured, claim| {
        component.* = .{ .allocator = a, .captured = captured, .preprocessed_logs = &key.fixed_logs, .z = z, .alpha = alpha, .claim = claim };
        try component.validate();
    }
    return out;
}
pub fn prove(a: std.mem.Allocator, key: *const Authority, values: []const Q) !Produced {
    try key.requireProverData();
    if (key.fixed == null) return error.Om31CircuitDeviceFixedRequiresDeviceProver;
    var base = try circuit.witness.trace.writeTrace(a, values, key.pp);
    defer base.deinit();
    if (!std.meta.eql(base.log_sizes, key.logs)) return error.InvalidOm31CircuitGeometry;
    const outputs = try a.dupe(Q, base.output_values);
    errdefer a.free(outputs);
    var channel = try begin(a, key, outputs);
    var scheme = try P.Engine.init(a, try P.targetConfig());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    try scheme.trees.ensureUnusedCapacity(a, 1);
    scheme.trees.appendAssumeCapacity(try key.retainFixed());
    P.MC.mixRoot(&channel, key.fixedRoot());
    // MAIN is generated and committed exactly once. Lookup arithmetic does not
    // rebuild the builder assignment or its table multiplicities.
    try scheme.commit(a, base.columns, &channel);
    const elements = draw(&channel);
    var interaction = try W.writeReleasing(a, &base, key.pp, elements.z, elements.alpha);
    defer interaction.deinit();
    channel.mixFelts(&interaction.claimed_sums.toArray());
    try scheme.commit(a, interaction.columns, &channel);
    const bound = try bind(a, key, elements.z, elements.alpha, interaction.claimed_sums);
    defer a.free(bound);
    const components = try a.alloc(Components.ComponentProver, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asProverComponent();
    owns = false;
    const proof = try P.Engine.prove(a, components, &channel, scheme, .{});
    return .{ .allocator = a, .outputs = outputs, .claims = interaction.claimed_sums, .proof = proof };
}
/// Independent fresh verifier state; published capture exists only on complete
/// success. Authority is supplied by the receiver, not rebuilt from proof logs.
pub fn verify(a: std.mem.Allocator, key: *const Authority, outputs: []const Q, claims: W.Claims, proof: *const P.Proof) !Capture {
    const pcs = &proof.commitment_scheme_proof;
    if (pcs.commitments.items.len != 4 or !std.meta.eql(pcs.config, try P.targetConfig())) return error.InvalidOm31CircuitProof;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.fixedRoot())) return error.InvalidOm31CircuitFixedRoot;
    var channel = try begin(a, key, outputs);
    const V = core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(P.H, P.MC);
    var receiver = try V.init(a, try P.targetConfig());
    defer receiver.deinit(a);
    try receiver.commit(a, key.fixedRoot(), &key.fixed_logs, &channel);
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
    const elements = draw(&channel);
    const terms = W.Elements.init(elements.z, elements.alpha);
    if (!(try W.lookupSum(outputs, claims, &terms)).isZero()) return error.InvalidOm31CircuitLookupSum;
    channel.mixFelts(&claims.toArray());
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
    const bound = try bind(a, key, elements.z, elements.alpha, claims);
    defer a.free(bound);
    const components = try a.alloc(CoreAir.Component, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asVerifierComponent();
    var capture: Capture = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(P.H, P.MC, a, components, &channel, &receiver, proof, &capture);
    return capture;
}
