//! Genuine new-profile ORIGINAL lookup theorem, optionally sharing one STARK
//! with typed native consumers. Native state/registers and all6lookup buses
//! close. Program/global memory remain OPEN. Default six-claim mode unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const K = @import("block_v8_range20_bytes_kernel_v1.zig");
const Profile = @import("block_v8_range20_bytes_profile_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const NativeLayout = @import("block_v8_native_endpoint_layout_v1.zig");
const Closure = @import("block_v8_native_endpoint_closure_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const Joined = @import("block_v6_joint_components_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations;
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const postcard = @import("interop_postcard");
pub const production_active = false;
pub const Trusted = struct { config: core.pcs.PcsConfig, layout: Profile.Layout, shape: ?*const Shape = null, elf: []const u8 = &.{}, elf_sha256: [32]u8 = @splat(0), execution_profile: @import("../runner/elf_loader.zig").ExecutionProfile = .rv32im_zkvm_v1, values: []const u32 = &.{} };
pub const Summary = struct { native_consumer: bool, range20_main_columns: u32 = 4, lookup_physical_claims: u32 = 7, all_lookup_buses_closed: bool = true, state_closed: bool, registers_closed: bool, program_open: Q, ram_open: Q, whole_vm_qualified: bool = false };
pub const Proof = struct {
    a: std.mem.Allocator,
    stark: S.Proof,
    native_claims: []Native.Claim,
    lookup: K.Claims,
    pub fn deinit(self: *Proof) void {
        const a = self.a;
        self.stark.deinit(a);
        a.free(self.native_claims);
        a.destroy(self);
    }
};
fn draw(a: std.mem.Allocator, ch: *S.Channel) !Epoch.Drawn {
    var compatibility = ch.*;
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, ch);
    const bytes = try @import("block_memory_relation_v2.zig").Challenges.drawFromChannel(a, &compatibility);
    if (!std.meta.eql(word.universal_prefix, bytes.universal_prefix)) return error.InvalidRange20Draw;
    const memory = @import("block_v7_memory_relations_v1.zig").draw(ch);
    return .{ .word = word, .bytes = bytes, .memory = memory, .channel = ch.* };
}
const Fixed = struct {
    a: std.mem.Allocator,
    native: []Column,
    lookup: [6]@import("block_v7_memory_trace_v1.zig").Matrix,
    all: []Column,
    fn create(a: std.mem.Allocator, t: Trusted) !Fixed {
        var n: std.ArrayList(Column) = .empty;
        errdefer {
            for (n.items) |c| a.free(c.values);
            n.deinit(a);
        }
        if (t.shape) |s| try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, s, 0, &n);
        var lookup = try Profile.Stage.fixed(a, t.layout);
        errdefer for (&lookup) |*m| m.deinit();
        const all = try a.alloc(Column, n.items.len + t.layout.columns[0]);
        errdefer a.free(all);
        @memcpy(all[0..n.items.len], n.items);
        var at = n.items.len;
        for (lookup) |m| {
            @memcpy(all[at..][0..m.columns.len], m.columns);
            at += m.columns.len;
        }
        return .{ .a = a, .native = try n.toOwnedSlice(a), .lookup = lookup, .all = all };
    }
    fn deinit(self: *Fixed) void {
        for (self.native) |c| self.a.free(c.values);
        self.a.free(self.native);
        for (&self.lookup) |*m| m.deinit();
        self.a.free(self.all);
    }
};
fn columns(a: std.mem.Allocator, stage: *const Profile.Stage, comptime main: bool) ![]Column {
    const count = stage.layout.columns[@intFromBool(main)];
    const out = try a.alloc(Column, count);
    var at: usize = 0;
    for (stage.matrices, stage.layout.parts) |m, p| {
        const cs = if (main) m.columns[p.width[0]..] else m.columns[0..p.width[0]];
        @memcpy(out[at..][0..cs.len], cs);
        at += cs.len;
    }
    return out;
}
pub fn For(comptime joint: bool) type {
    const trees = if (joint) 5 else 3;
    const maps = if (joint) .{ [_]usize{ 0, 1, 3 }, [_]usize{ 0, 2, 4 } } else .{[_]usize{ 0, 1, 2 }};
    return struct {
        fn admit(a: std.mem.Allocator, t: Trusted) !?Image.Owned {
            try t.layout.validate();
            if (joint) {
                const shape = t.shape orelse return error.InvalidRange20Mode;
                try shape.validateBlake3Execution();
                if (t.values.len != 0) return error.InvalidRange20Mode;
                var image = try Image.Owned.init(a, t.elf, t.elf_sha256, t.execution_profile, .{});
                errdefer image.deinit();
                if (!std.meta.eql(image.root, shape.public_data.program_root.?)) return error.InvalidRange20ProgramRoot;
                return image;
            }
            if (t.shape != null or t.values.len >= core.fields.m31.Modulus) return error.InvalidRange20Mode;
            for (t.values) |v| if (v >= 1 << 20) return error.InvalidRange20Value;
            return null;
        }
        fn mix(ch: *S.Channel, t: Trusted, nd: [32]u8) void {
            ch.mixU32s(&.{ K.TAG, K.VERSION, 7, @intFromBool(joint) });
            t.config.mixInto(ch);
            ch.mixRoot(t.layout.digest);
            ch.mixRoot(nd);
            if (joint) {
                ch.mixRoot(t.elf_sha256);
                t.shape.?.public_data.mixInto(ch);
                t.shape.?.mixShardManifest(ch);
            } else {
                ch.mixU32s(&.{@intCast(t.values.len)});
                ch.mixU32s(t.values);
            }
        }
        fn close(a: std.mem.Allocator, t: Trusted, drawn: Epoch.Drawn, native: ?*const Native.Owner, nc: []const Native.Claim, c: K.Claims) !Summary {
            const shared = try Shared.init(&drawn.word.universal_prefix);
            var requests: [6]Q = @splat(Q.zero());
            var program = Q.zero();
            var ram = Q.zero();
            if (joint) {
                const parts = try Closure.extract(a, t.shape.?, 0, native.?.layout.slots, nc);
                requests = parts.table_requests;
                const Public = @import("../air/public_logup_arithmetic.zig");
                if (!(try Public.registersStateSumFor(Q, &t.shape.?.public_data, &shared.native)).add(parts.state_sum).isZero()) return error.UnclosedRange20State;
                if (!(try Public.registerMemoryAccessSumFor(Q, &t.shape.?.public_data, &shared.native)).add(parts.register_sum).add(parts.register_clock_sum).isZero()) return error.UnclosedRange20Registers;
                const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(t.execution_profile, &t.shape.?.public_data, &drawn.word.universal_prefix);
                program = parts.program_sum.add(boundary.sum);
                ram = parts.ordinary_ram_sum.add(parts.ram_clock_sum);
            } else {
                const relation = @import("block_v7_memory_relations_v1.zig").Relation(Q, 1).from(shared.native.range_check_20);
                for (t.values) |v| requests[1] = requests[1].sub(try Q.one().div(relation.combineSecure(.{Q.fromBase(M.fromCanonical(v))})));
            }
            for (requests, c.native, 0..) |req, supply, i| {
                var residual = req.add(supply);
                if (i == 4) residual = residual.add(c.range20_bytes);
                if (!residual.isZero()) return error.UnclosedRange20Lookup;
            }
            return .{ .native_consumer = joint, .state_closed = joint, .registers_closed = joint, .program_open = program, .ram_open = ram };
        }
        pub fn produce(a: std.mem.Allocator, t: Trusted, stage: *const Profile.Stage, main: []const Column) !*Proof {
            if (!std.meta.eql(stage.layout, t.layout)) return error.InvalidRange20Profile;
            var image = try admit(a, t);
            defer if (image) |*v| v.deinit();
            var nl: ?NativeLayout.Layout = if (joint) try NativeLayout.Layout.init(a, t.shape.?, 0) else null;
            defer if (nl) |*v| v.deinit();
            var fixed = try Fixed.create(a, t);
            defer fixed.deinit();
            var guard: ?Halt.Owned = if (joint) try Halt.prepare(a, t.shape.?, main, .{ .halt_address = image.?.info.halt_flag }) else null;
            defer if (guard) |*v| v.deinit();
            if (!joint and main.len != 0) return error.InvalidRange20Mode;
            var scheme = try Scheme.init(a, t.config);
            var live = true;
            defer if (live) scheme.deinit(a);
            var ch = S.Channel{};
            mix(&ch, t, if (joint) nl.?.digest else @splat(0));
            try scheme.commitBorrowedStreaming(a, fixed.all, 8, &ch);
            if (joint) try scheme.commitBorrowedStreaming(a, guard.?.columns, 8, &ch);
            const mc = try columns(a, stage, true);
            defer a.free(mc);
            try scheme.commitBorrowedStreaming(a, mc, 8, &ch);
            const drawn = try draw(a, &ch);
            const shared = try Shared.init(&drawn.word.universal_prefix);
            var ni: ?Native.Interactions = if (joint) try Native.Interactions.generate(a, t.shape.?, guard.?.columns, &drawn) else null;
            defer if (ni) |*v| v.deinit();
            var generated = try Profile.Generated.create(a, stage, shared);
            defer generated.deinit();
            const nc: []const Native.Claim = if (joint) ni.?.claims else &.{};
            if (joint) try Native.recordClaims(&ch, nl.?.digest, nc);
            try K.recordClaims(&ch, generated.claims);
            const no: ?*Native.Owner = if (joint) try Native.Owner.initWithHalt(a, t.shape.?, nc, &drawn, .{ .halt_address = image.?.info.halt_flag }) else null;
            defer if (no) |n| n.deinit();
            _ = try close(a, t, drawn, no, nc, generated.claims);
            if (joint) try scheme.commitBorrowedStreaming(a, ni.?.columns, 8, &ch);
            try scheme.commitBorrowedStreaming(a, generated.columns, 8, &ch);
            const lo = try Profile.Owner.create(a, t.layout, shared, generated.claims);
            defer lo.deinit();
            var nb: if (joint) Joined.Combined(true) else void = if (joint) try no.?.proving() else {};
            defer if (joint) nb.deinit(a);
            const parts = if (joint) .{ nb.handles, &lo.provers } else .{&lo.provers};
            const widths = if (joint) .{ no.?.fixed.len, @as(usize, t.layout.columns[0]) } else .{@as(usize, t.layout.columns[0])};
            var placed = try Placement.For(maps, trees, true).init(a, parts, widths);
            defer placed.deinit(a);
            const out = try a.create(Proof);
            errdefer a.destroy(out);
            const copied = try a.dupe(Native.Claim, nc);
            errdefer a.free(copied);
            live = false;
            out.* = .{ .a = a, .native_claims = copied, .lookup = generated.claims, .stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, placed.handles, &ch, scheme) };
            return out;
        }
        pub fn verify(a: std.mem.Allocator, t: Trusted, stark: *const S.Proof, nc: []const Native.Claim, claims: K.Claims) !Summary {
            var image = try admit(a, t);
            defer if (image) |*v| v.deinit();
            var nl: ?NativeLayout.Layout = if (joint) try NativeLayout.Layout.init(a, t.shape.?, 0) else null;
            defer if (nl) |*v| v.deinit();
            const roots = stark.commitment_scheme_proof.commitments.items;
            if (roots.len != trees + 1 or !std.meta.eql(t.config, stark.commitment_scheme_proof.config) or (!joint and nc.len != 0)) return error.InvalidRange20ProofGeometry;
            var f = try Fixed.create(a, t);
            defer f.deinit();
            var key = try Scheme.init(a, t.config);
            defer key.deinit(a);
            var ignored = S.Channel{};
            try key.commitBorrowedStreaming(a, f.all, 8, &ignored);
            if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedRange20FixedKey;
            var ch = S.Channel{};
            mix(&ch, t, if (joint) nl.?.digest else @splat(0));
            var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, t.config);
            defer verifier.deinit(a);
            const fl = try a.alloc(u32, f.all.len);
            defer a.free(fl);
            for (f.all, fl) |c, *l| l.* = c.log_size;
            try verifier.commit(a, roots[0], fl, &ch);
            if (joint) {
                const ml = try Halt.mainLogs(a, t.shape.?);
                defer a.free(ml);
                try verifier.commit(a, roots[1], ml, &ch);
            }
            const mainlogs = try logs(a, t.layout, 1);
            defer a.free(mainlogs);
            try verifier.commit(a, roots[if (joint) 2 else 1], mainlogs, &ch);
            const drawn = try draw(a, &ch);
            const shared = try Shared.init(&drawn.word.universal_prefix);
            if (joint) try Native.recordClaims(&ch, nl.?.digest, nc);
            try K.recordClaims(&ch, claims);
            const no: ?*Native.Owner = if (joint) try Native.Owner.initWithHalt(a, t.shape.?, nc, &drawn, .{ .halt_address = image.?.info.halt_flag }) else null;
            defer if (no) |n| n.deinit();
            if (joint) try verifier.commit(a, roots[3], no.?.interactions, &ch);
            const il = try logs(a, t.layout, 2);
            defer a.free(il);
            try verifier.commit(a, roots[if (joint) 4 else 2], il, &ch);
            const lo = try Profile.Owner.create(a, t.layout, shared, claims);
            defer lo.deinit();
            var nb: if (joint) Joined.Combined(false) else void = if (joint) try no.?.verifying() else {};
            defer if (joint) nb.deinit(a);
            const parts = if (joint) .{ nb.handles, &lo.verifiers } else .{&lo.verifiers};
            const widths = if (joint) .{ no.?.fixed.len, @as(usize, t.layout.columns[0]) } else .{@as(usize, t.layout.columns[0])};
            var placed = try Placement.For(maps, trees, false).init(a, parts, widths);
            defer placed.deinit(a);
            var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, placed.handles, &ch, &verifier, stark, &capture);
            defer capture.deinit(a);
            return close(a, t, drawn, no, nc, claims);
        }
        pub fn encode(a: std.mem.Allocator, proof: *const Proof) ![]u8 {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(a);
            try postcard.serializeProof(S.Hasher, bytes.writer(a), proof.stark);
            if (proof.native_claims.len > 65536 or bytes.items.len > 16 << 20) return error.InvalidRange20Envelope;
            const header = 24 + 24 * proof.native_claims.len + 7 * 16;
            const out = try a.alloc(u8, header + bytes.items.len);
            errdefer a.free(out);
            @memcpy(out[0..8], "B8R20B01");
            std.mem.writeInt(u32, out[8..12], @intFromBool(joint), .little);
            std.mem.writeInt(u32, out[12..16], 7, .little);
            std.mem.writeInt(u32, out[16..20], @intCast(proof.native_claims.len), .little);
            std.mem.writeInt(u32, out[20..24], @intCast(bytes.items.len), .little);
            var offset: usize = 24;
            for (proof.native_claims) |c| {
                writeQ(out, &offset, c.sum);
                std.mem.writeInt(u64, out[offset..][0..8], c.row_count, .little);
                offset += 8;
            }
            for (proof.lookup.native) |q| writeQ(out, &offset, q);
            writeQ(out, &offset, proof.lookup.range20_bytes);
            @memcpy(out[header..], bytes.items);
            return out;
        }
        pub fn verifyBytes(a: std.mem.Allocator, t: Trusted, raw: []const u8) !Summary {
            if (raw.len < 24 + 112 or !std.mem.eql(u8, raw[0..8], "B8R20B01") or std.mem.readInt(u32, raw[8..12], .little) != @intFromBool(joint) or std.mem.readInt(u32, raw[12..16], .little) != 7) return error.InvalidRange20Envelope;
            try t.layout.validate();
            const n = std.mem.readInt(u32, raw[16..20], .little);
            var nl: ?NativeLayout.Layout = if (joint) try NativeLayout.Layout.init(a, t.shape orelse return error.InvalidRange20Mode, 0) else null;
            defer if (nl) |*v| v.deinit();
            if (n > 65536 or n != (if (joint) nl.?.slots.len else 0)) return error.InvalidRange20Envelope;
            const header = 24 + 24 * @as(usize, n) + 7 * 16;
            if (raw.len < header or raw.len - header > 16 << 20 or std.mem.readInt(u32, raw[20..24], .little) != raw.len - header) return error.InvalidRange20Envelope;
            const nc = try a.alloc(Native.Claim, n);
            defer a.free(nc);
            var offset: usize = 24;
            for (nc) |*c| {
                c.sum = try readQ(raw, &offset);
                c.row_count = std.mem.readInt(u64, raw[offset..][0..8], .little);
                offset += 8;
            }
            var claims: K.Claims = undefined;
            for (&claims.native) |*q| q.* = try readQ(raw, &offset);
            claims.range20_bytes = try readQ(raw, &offset);
            var counts: [trees + 1]u32 = undefined;
            var maxlog: u32 = 4;
            for (t.layout.parts) |part| maxlog = @max(maxlog, part.log);
            if (joint) {
                const fl = try Template.columnLogs(a, t.shape.?, 0, .fixed);
                defer a.free(fl);
                const ml = try Halt.mainLogs(a, t.shape.?);
                defer a.free(ml);
                const il = try Fused.interactionLogs(a, nl.?.slots, &.{});
                defer a.free(il);
                counts = .{ @intCast(fl.len + t.layout.columns[0]), @intCast(ml.len), t.layout.columns[1], @intCast(il.len), t.layout.columns[2], 16 };
                for (fl) |l| maxlog = @max(maxlog, l);
                for (ml) |l| maxlog = @max(maxlog, l);
                for (il) |l| maxlog = @max(maxlog, l);
            } else counts = .{ t.layout.columns[0], t.layout.columns[1], t.layout.columns[2], 16 };
            const empty: [trees + 1]bool = @splat(false);
            const widths: [trees + 1]u32 = @splat(6);
            const config = t.config;
            try postcard.proof_preflight.validateRuntime(raw[header..], .{ .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size }, .tree_columns = &counts, .empty_tree_flags = &empty, .sample_width_limits = &widths, .allow_zero_samples = true, .max_column_log_size = maxlog, .max_merkle_column_log_size = maxlog, .hash_size = 32, .max_wire_bytes = 16 << 20 });
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var stream = std.io.fixedBufferStream(raw[header..]);
            const proof = try postcard.deserializeProof(S.Hasher, arena.allocator(), stream.reader());
            if (stream.pos != raw.len - header) return error.InvalidRange20Envelope;
            return verify(a, t, &proof, nc, claims);
        }
    };
}
fn logs(a: std.mem.Allocator, layout: Profile.Layout, tree: usize) ![]u32 {
    const out = try a.alloc(u32, layout.columns[tree]);
    for (layout.parts) |p| @memset(out[p.offset[tree]..][0..p.width[tree]], p.log);
    return out;
}

fn writeQ(out: []u8, offset: *usize, q: Q) void {
    for (q.toM31Array()) |v| {
        std.mem.writeInt(u32, out[offset.*..][0..4], v.v, .little);
        offset.* += 4;
    }
}
fn readQ(raw: []const u8, offset: *usize) !Q {
    var limbs: [4]M = undefined;
    for (&limbs) |*v| {
        const n = std.mem.readInt(u32, raw[offset.*..][0..4], .little);
        if (n >= core.fields.m31.Modulus) return error.InvalidRange20Envelope;
        v.* = M.fromCanonical(n);
        offset.* += 4;
    }
    return Q.fromM31Array(limbs);
}
