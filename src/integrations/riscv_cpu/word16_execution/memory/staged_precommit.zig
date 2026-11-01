//! Non-accepting two-phase global RAM stage-one transcript prototype.
//! Roots here come from actual PCS commitments and are independently checked
//! against a complete expected roster before any shared challenge is drawn.
//! This is NOT a full execution proof or a replacement for the private RAM
//! root-chain verifier. The final physical CPU/service event-join and aggregate
//! receiver are intentionally absent.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("global_manifest.zig");
pub const Digest = G.Digest;
pub const Receipt = G.Receipt;
pub const Expected = G.Expected;
pub const Anchors = G.ExecutionAnchors;

const MAX_SCOPED = 4096;

fn seal(expected: Expected, anchors: Anchors, receipts: []const Receipt) Digest {
    var ch = G.P.Channel{};
    ch.mixU32s(&.{ 0x52564750, 1, 14, 19, 13 }); // RVGP revision 1
    G.P.config().mixInto(&ch);
    for ([_]Digest{ expected.context.execution, expected.context.program, expected.context.image, expected.context.policy, expected.context.opcode_map, anchors.initial_registers, anchors.terminal_registers }) |value|
        G.mixDigest(&ch, value);
    ch.mixU64(expected.context.total_steps);
    ch.mixU64(anchors.initial_pc);
    ch.mixU64(anchors.terminal_pc);
    ch.mixU64(anchors.total_steps);
    ch.mixU64(expected.specs.len);
    for (expected.specs, receipts, 0..) |spec, receipt, i| {
        ch.mixU64(i);
        G.mixDigest(&ch, G.specDigest(spec));
        G.mixDigest(&ch, receipt.fixed.bytes);
        G.mixDigest(&ch, receipt.main.bytes);
    }
    return ch.digestBytes();
}
fn derive(comptime R: type, ch: *G.P.Channel, tag: u32) R {
    ch.mixU32s(&.{ 0x52564743, 1, tag }); // RVGC
    var out: R = undefined;
    out.offset = ch.drawSecureFelt();
    for (&out.coefficients) |*v| v.* = ch.drawSecureFelt();
    return out;
}
fn validateReceipt(spec: G.Spec, receipt: Receipt) !void {
    if (receipt.ordinal != spec.ordinal or
        !std.mem.eql(u8, &receipt.spec_digest, &G.specDigest(spec)) or
        !std.mem.eql(u8, &receipt.fixed.bytes, &spec.fixed.bytes))
        return error.StagedGlobalReceiptMismatch;
}

pub const Plan = struct {
    allocator: std.mem.Allocator,
    anchors: Anchors,
    context: G.Context,
    specs: []G.Spec,
    receipts: []Receipt,
    stage1_checked: []bool,
    digest: Digest,

    pub fn init(a: std.mem.Allocator, expected: Expected, anchors: Anchors, receipts: []const Receipt) !Plan {
        // Validate EVERYTHING independently of producer receipts before
        // ownership/allocation. A missing/duplicate shard cannot be 'filled'
        // with an arbitrary later root after the challenge is selected.
        try G.validateStagedExecutionPlan(expected, anchors);
        if (expected.specs.len != receipts.len or receipts.len > MAX_SCOPED)
            return error.IncompleteStagedGlobalPrecommit;
        for (expected.specs, receipts) |spec, receipt| try validateReceipt(spec, receipt);
        const ss = try a.alloc(G.Spec, expected.specs.len);
        errdefer a.free(ss);
        var n: usize = 0;
        errdefer for (ss[0..n]) |spec| {
            a.free(spec.fixed_logs);
            a.free(spec.main_logs);
        };
        for (ss, expected.specs) |*dst, source| {
            const fixed = try a.dupe(u32, source.fixed_logs);
            errdefer a.free(fixed);
            const main = try a.dupe(u32, source.main_logs);
            dst.* = source;
            dst.fixed_logs = fixed;
            dst.main_logs = main;
            n += 1;
        }
        const rr = try a.dupe(Receipt, receipts);
        errdefer a.free(rr);
        const checks = try a.alloc(bool, receipts.len);
        @memset(checks, false);
        return .{ .allocator = a, .anchors = anchors, .context = expected.context, .specs = ss, .receipts = rr, .stage1_checked = checks, .digest = seal(expected, anchors, receipts) };
    }
    pub fn deinit(self: *Plan) void {
        for (self.specs) |spec| {
            self.allocator.free(spec.fixed_logs);
            self.allocator.free(spec.main_logs);
        }
        self.allocator.free(self.specs);
        self.allocator.free(self.receipts);
        self.allocator.free(self.stage1_checked);
        self.* = undefined;
    }
    pub fn check(self: *const Plan) !void {
        const e = Expected{ .context = self.context, .specs = self.specs };
        try G.validateStagedExecutionPlan(e, self.anchors);
        if (self.specs.len != self.receipts.len or self.stage1_checked.len != self.specs.len) return error.IncompleteStagedGlobalPrecommit;
        for (self.specs, self.receipts) |spec, receipt| try validateReceipt(spec, receipt);
        if (!std.mem.eql(u8, &self.digest, &seal(e, self.anchors, self.receipts)))
            return error.StagedGlobalPrecommitChanged;
    }
    /// Physical stage-one custody check. This checks the PCS-generated fixed
    /// and MAIN roots and geometry, but it is *not* verification of a proof's
    /// execution constraints. Full receiver promotion is a different gate.
    pub fn verifyStage1(self: *Plan, a: std.mem.Allocator, ordinal: usize, scheme: *G.Scheme) !void {
        try self.check();
        if (ordinal >= self.specs.len) return error.InvalidStagedGlobalOrdinal;
        const actual = try G.fromCommitted(a, scheme, self.specs[ordinal]);
        if (!std.meta.eql(actual, self.receipts[ordinal])) return error.StagedGlobalStage1RootMismatch;
        self.stage1_checked[ordinal] = true;
    }
    /// This is deliberately named "diagnostic": the returned challenges are
    /// not admitted by any production prover or native verifier. Unlike a
    /// self-sealed host manifest, challenge publication additionally requires
    /// a successful current PCS root check for EVERY recorded participant.
    pub fn diagnosticChallenges(self: *const Plan) !G.Shared {
        try self.check();
        for (self.stage1_checked) |checked| if (!checked) return error.IncompleteStagedPhysicalPrecommit;
        var ch = G.P.Channel{};
        ch.mixU32s(&.{ 0x52564741, 1 }); // RVGA
        G.mixDigest(&ch, self.digest);
        return .{
            .ram = derive(@TypeOf(@as(G.Shared, undefined).ram), &ch, 14),
            .owner = derive(@TypeOf(@as(G.Shared, undefined).owner), &ch, 19),
            .function = derive(@TypeOf(@as(G.Shared, undefined).function), &ch, 13),
        };
    }
};
