//! New sparse-ROM source identity: canonical original program AIR plus optional
//! typed native original. No default source dispatch or whole-VM claim.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Source = @import("block_v8_sparse_rom_v1.zig");
const ROM = @import("block_v8_sparse_rom_component_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Layout = @import("block_v8_native_endpoint_layout_v1.zig");
const Closure = @import("block_v8_native_endpoint_closure_v1.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const Joined = @import("block_v6_joint_components_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const postcard = @import("interop_postcard");
pub const production_active = false;
pub const Trusted = struct { rom: Source.Trusted, config: core.pcs.PcsConfig, shape: ?*const Shape = null };
pub const Summary = struct { selected_pcs: u32, sparse_log: u32, complete_rom_rows: u64, fetch_count: u64, program_closed: bool, state_closed: bool, registers_closed: bool, ram_open: Q, table_requests: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q, whole_vm_qualified: bool = false };
pub const Proof = struct {
    a: std.mem.Allocator,
    stark: S.Proof,
    native_claims: []Native.Claim,
    rom_claim: Q,
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
    if (!std.meta.eql(word.universal_prefix, bytes.universal_prefix)) return error.InvalidSparseRomDraw;
    const memory = @import("block_v7_memory_relations_v1.zig").draw(ch);
    return .{ .word = word, .bytes = bytes, .memory = memory, .channel = ch.* };
}
fn mix(ch: *S.Channel, t: Trusted, plan: *const Source.Owned, comptime joint: bool, layout: [32]u8) void {
    ch.mixU32s(&.{ Source.TAG, Source.VERSION, @intFromBool(joint) });
    t.config.mixInto(ch);
    ch.mixRoot(plan.digest);
    ch.mixRoot(layout);
    if (joint) {
        t.shape.?.public_data.mixInto(ch);
        t.shape.?.mixShardManifest(ch);
    }
}
const Fixed = struct {
    a: std.mem.Allocator,
    native: []Column,
    rom: [6]Column,
    all: []Column,
    fn create(a: std.mem.Allocator, plan: *const Source.Owned, shape: ?*const Shape) !Fixed {
        var list: std.ArrayList(Column) = .empty;
        errdefer {
            for (list.items) |c| a.free(c.values);
            list.deinit(a);
        }
        if (shape) |s| try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, s, 0, &list);
        const rom = try plan.fixedColumns(a);
        errdefer for (rom) |c| a.free(c.values);
        const all = try a.alloc(Column, list.items.len + 6);
        errdefer a.free(all);
        @memcpy(all[0..list.items.len], list.items);
        @memcpy(all[list.items.len..], &rom);
        return .{ .a = a, .native = try list.toOwnedSlice(a), .rom = rom, .all = all };
    }
    fn deinit(self: *Fixed) void {
        for (self.native) |c| self.a.free(c.values);
        for (self.rom) |c| self.a.free(c.values);
        self.a.free(self.native);
        self.a.free(self.all);
    }
};
pub fn For(comptime joint: bool) type {
    const trace_trees = if (joint) 5 else 3;
    const maps = if (joint) .{ [_]usize{ 0, 1, 3 }, [_]usize{ 0, 2, 4 } } else .{[_]usize{ 0, 1, 2 }};
    return struct {
        fn admit(a: std.mem.Allocator, t: Trusted, entries: []const Source.Entry) !Source.Owned {
            if (joint) {
                const shape = t.shape orelse return error.InvalidSparseRomMode;
                try shape.validateBlake3Execution();
                if (!std.meta.eql(shape.public_data.program_root.?.bytes, t.rom.program_root.bytes)) return error.UntrustedSparseRomNativeRoot;
            } else if (t.shape != null) return error.InvalidSparseRomMode;
            return Source.Owned.derive(a, t.rom, entries, .{});
        }
        fn close(a: std.mem.Allocator, t: Trusted, plan: *const Source.Owned, drawn: Epoch.Drawn, native: ?*const Native.Owner, claims: []const Native.Claim, rom: Q) !Summary {
            var out = Summary{ .selected_pcs = @intCast(plan.entries.len), .sparse_log = plan.log_size, .complete_rom_rows = plan.full_instruction_rows, .fetch_count = t.rom.expected_fetches, .program_closed = false, .state_closed = false, .registers_closed = false, .ram_open = Q.zero(), .table_requests = @splat(Q.zero()) };
            if (joint) {
                const shape = t.shape.?;
                const prefix = &drawn.word.universal_prefix;
                const parts = try Closure.extract(a, shape, 0, native.?.layout.slots, claims);
                const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(t.rom.profile, &shape.public_data, prefix);
                if (parts.fetch_count + boundary.fetch_count != t.rom.expected_fetches or !parts.program_sum.add(boundary.sum).add(rom).isZero()) return error.UnclosedSparseRomRequests;
                const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(prefix);
                const Public = @import("../air/public_logup_arithmetic.zig");
                if (!(try Public.registersStateSumFor(Q, &shape.public_data, &shared.native)).add(parts.state_sum).isZero()) return error.UnclosedSparseRomState;
                if (!(try Public.registerMemoryAccessSumFor(Q, &shape.public_data, &shared.native)).add(parts.register_sum).add(parts.register_clock_sum).isZero()) return error.UnclosedSparseRomRegisters;
                out.program_closed = true;
                out.state_closed = true;
                out.registers_closed = true;
                out.ram_open = parts.ordinary_ram_sum.add(parts.ram_clock_sum);
                out.table_requests = parts.table_requests;
            }
            return out;
        }
        pub fn produce(a: std.mem.Allocator, t: Trusted, entries: []const Source.Entry, main: []const Column) !*Proof {
            var plan = try admit(a, t, entries);
            defer plan.deinit();
            var layout: ?Layout.Layout = if (joint) try Layout.Layout.init(a, t.shape.?, 0) else null;
            defer if (layout) |*v| v.deinit();
            var f = try Fixed.create(a, &plan, t.shape);
            defer f.deinit();
            var guard: ?Halt.Owned = if (joint) try Halt.prepare(a, t.shape.?, main, .{ .halt_address = plan.halt_address }) else null;
            defer if (guard) |*g| g.deinit();
            if (!joint and main.len != 0) return error.InvalidSparseRomMode;
            var scheme = try Scheme.init(a, t.config);
            var live = true;
            defer if (live) scheme.deinit(a);
            var ch = S.Channel{};
            mix(&ch, t, &plan, joint, if (joint) layout.?.digest else @splat(0));
            try scheme.commitBorrowedStreaming(a, f.all, 8, &ch);
            if (joint) try scheme.commitBorrowedStreaming(a, guard.?.columns, 8, &ch);
            try scheme.commitBorrowedStreaming(a, &.{}, 8, &ch);
            const drawn = try draw(a, &ch);
            var ni: ?Native.Interactions = if (joint) try Native.Interactions.generate(a, t.shape.?, guard.?.columns, &drawn) else null;
            defer if (ni) |*v| v.deinit();
            const ro = try ROM.Owner.create(a, &plan, drawn.word.universal_prefix, null);
            defer ro.deinit();
            const nc: []const Native.Claim = if (joint) ni.?.claims else &.{};
            if (joint) try Native.recordClaims(&ch, layout.?.digest, nc);
            try ROM.recordClaim(&ch, plan.digest, ro.claim);
            const no: ?*Native.Owner = if (joint) try Native.Owner.initWithHalt(a, t.shape.?, nc, &drawn, .{ .halt_address = plan.halt_address }) else null;
            defer if (no) |n| n.deinit();
            _ = try close(a, t, &plan, drawn, no, nc, ro.claim);
            if (joint) try scheme.commitBorrowedStreaming(a, ni.?.columns, 8, &ch);
            try scheme.commitBorrowedStreaming(a, ro.interaction, 8, &ch);
            var nb: if (joint) Joined.Combined(true) else void = if (joint) try no.?.proving() else {};
            defer if (joint) nb.deinit(a);
            const parts = if (joint) .{ nb.handles, &.{ro.prover} } else .{&.{ro.prover}};
            const widths = if (joint) .{ no.?.fixed.len, @as(usize, 6) } else .{@as(usize, 6)};
            var placed = try Placement.For(maps, trace_trees, true).init(a, parts, widths);
            defer placed.deinit(a);
            const out = try a.create(Proof);
            errdefer a.destroy(out);
            const copied = try a.dupe(Native.Claim, nc);
            errdefer a.free(copied);
            live = false;
            out.* = .{ .a = a, .native_claims = copied, .rom_claim = ro.claim, .stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, placed.handles, &ch, scheme) };
            return out;
        }
        pub fn verify(a: std.mem.Allocator, t: Trusted, entries: []const Source.Entry, stark: *const S.Proof, nc: []const Native.Claim, rc: Q) !Summary {
            var plan = try admit(a, t, entries);
            defer plan.deinit();
            var layout: ?Layout.Layout = if (joint) try Layout.Layout.init(a, t.shape.?, 0) else null;
            defer if (layout) |*v| v.deinit();
            if (!joint and nc.len != 0) return error.InvalidSparseRomMode;
            const roots = stark.commitment_scheme_proof.commitments.items;
            if (roots.len != trace_trees + 1 or !std.meta.eql(t.config, stark.commitment_scheme_proof.config)) return error.InvalidSparseRomProofGeometry;
            var f = try Fixed.create(a, &plan, t.shape);
            defer f.deinit();
            var key = try Scheme.init(a, t.config);
            defer key.deinit(a);
            var ignored = S.Channel{};
            try key.commitBorrowedStreaming(a, f.all, 8, &ignored);
            if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedSparseRomFixedKey;
            var ch = S.Channel{};
            mix(&ch, t, &plan, joint, if (joint) layout.?.digest else @splat(0));
            var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, t.config);
            defer verifier.deinit(a);
            const fl = try a.alloc(u32, f.all.len);
            defer a.free(fl);
            for (f.all, fl) |c, *v| v.* = c.log_size;
            try verifier.commit(a, roots[0], fl, &ch);
            const main_logs = if (joint) try Halt.mainLogs(a, t.shape.?) else try a.alloc(u32, 0);
            defer a.free(main_logs);
            if (joint) try verifier.commit(a, roots[1], main_logs, &ch);
            try verifier.commit(a, roots[if (joint) 2 else 1], &.{}, &ch);
            const drawn = try draw(a, &ch);
            if (joint) try Native.recordClaims(&ch, layout.?.digest, nc);
            try ROM.recordClaim(&ch, plan.digest, rc);
            const no: ?*Native.Owner = if (joint) try Native.Owner.initWithHalt(a, t.shape.?, nc, &drawn, .{ .halt_address = plan.halt_address }) else null;
            defer if (no) |n| n.deinit();
            if (joint) try verifier.commit(a, roots[3], no.?.interactions, &ch);
            const il: [4]u32 = @splat(plan.log_size);
            try verifier.commit(a, roots[if (joint) 4 else 2], &il, &ch);
            const ro = try ROM.Owner.create(a, &plan, drawn.word.universal_prefix, rc);
            defer ro.deinit();
            var nb: if (joint) Joined.Combined(false) else void = if (joint) try no.?.verifying() else {};
            defer if (joint) nb.deinit(a);
            const parts = if (joint) .{ nb.handles, &.{ro.verifier} } else .{&.{ro.verifier}};
            const widths = if (joint) .{ no.?.fixed.len, @as(usize, 6) } else .{@as(usize, 6)};
            var placed = try Placement.For(maps, trace_trees, false).init(a, parts, widths);
            defer placed.deinit(a);
            var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, placed.handles, &ch, &verifier, stark, &capture);
            defer capture.deinit(a);
            return close(a, t, &plan, drawn, no, nc, rc);
        }

        pub fn encode(a: std.mem.Allocator, proof: *const Proof) ![]u8 {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(a);
            try postcard.serializeProof(S.Hasher, bytes.writer(a), proof.stark);
            if (bytes.items.len > 16 << 20 or proof.native_claims.len > 65536) return error.InvalidSparseRomEnvelope;
            const header = 24 + 24 * proof.native_claims.len + 16;
            const out = try a.alloc(u8, header + bytes.items.len);
            errdefer a.free(out);
            @memcpy(out[0..8], "B8SPROM1");
            std.mem.writeInt(u32, out[8..12], Source.VERSION, .little);
            std.mem.writeInt(u32, out[12..16], @intFromBool(joint), .little);
            std.mem.writeInt(u32, out[16..20], @intCast(proof.native_claims.len), .little);
            std.mem.writeInt(u32, out[20..24], @intCast(bytes.items.len), .little);
            var offset: usize = 24;
            for (proof.native_claims) |c| {
                writeQ(out, &offset, c.sum);
                std.mem.writeInt(u64, out[offset..][0..8], c.row_count, .little);
                offset += 8;
            }
            writeQ(out, &offset, proof.rom_claim);
            @memcpy(out[header..], bytes.items);
            return out;
        }
        pub fn verifyBytes(a: std.mem.Allocator, t: Trusted, entries: []const Source.Entry, raw: []const u8) !Summary {
            if (raw.len < 40 or !std.mem.eql(u8, raw[0..8], "B8SPROM1") or std.mem.readInt(u32, raw[8..12], .little) != Source.VERSION or std.mem.readInt(u32, raw[12..16], .little) != @intFromBool(joint)) return error.InvalidSparseRomEnvelope;
            var plan = try admit(a, t, entries);
            defer plan.deinit();
            var layout: ?Layout.Layout = if (joint) try Layout.Layout.init(a, t.shape.?, 0) else null;
            defer if (layout) |*v| v.deinit();
            const n = std.mem.readInt(u32, raw[16..20], .little);
            if (n > 65536 or n != (if (joint) layout.?.slots.len else 0)) return error.InvalidSparseRomEnvelope;
            const header = 40 + 24 * @as(usize, n);
            if (raw.len < header or raw.len - header > 16 << 20 or std.mem.readInt(u32, raw[20..24], .little) != raw.len - header) return error.InvalidSparseRomEnvelope;
            const nc = try a.alloc(Native.Claim, n);
            defer a.free(nc);
            var offset: usize = 24;
            for (nc) |*c| {
                c.sum = try readQ(raw, &offset);
                c.row_count = std.mem.readInt(u64, raw[offset..][0..8], .little);
                offset += 8;
            }
            const rc = try readQ(raw, &offset);
            var counts: [trace_trees + 1]u32 = undefined;
            var empty: [trace_trees + 1]bool = @splat(false);
            const widths: [trace_trees + 1]u32 = @splat(6);
            var max_log = plan.log_size;
            if (joint) {
                const fl = try Template.columnLogs(a, t.shape.?, 0, .fixed);
                defer a.free(fl);
                const ml = try Halt.mainLogs(a, t.shape.?);
                defer a.free(ml);
                const il = try Fused.interactionLogs(a, layout.?.slots, &.{});
                defer a.free(il);
                counts = .{ @intCast(fl.len + 6), @intCast(ml.len), 0, @intCast(il.len), 4, 16 };
                empty[2] = true;
                for (fl) |l| max_log = @max(max_log, l);
                for (ml) |l| max_log = @max(max_log, l);
                for (il) |l| max_log = @max(max_log, l);
            } else {
                counts = .{ 6, 0, 4, 16 };
                empty[1] = true;
            }
            const config = t.config;
            try postcard.proof_preflight.validateRuntime(raw[header..], .{ .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size }, .tree_columns = &counts, .empty_tree_flags = &empty, .sample_width_limits = &widths, .allow_zero_samples = true, .max_column_log_size = max_log, .max_merkle_column_log_size = max_log, .hash_size = 32, .max_wire_bytes = 16 << 20 });
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var stream = std.io.fixedBufferStream(raw[header..]);
            const proof = try postcard.deserializeProof(S.Hasher, arena.allocator(), stream.reader());
            if (stream.pos != raw.len - header) return error.InvalidSparseRomEnvelope;
            return verify(a, t, entries, &proof, nc, rc);
        }
    };
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
        if (n >= core.fields.m31.Modulus) return error.InvalidSparseRomEnvelope;
        v.* = M.fromCanonical(n);
        offset.* += 4;
    }
    return Q.fromM31Array(limbs);
}
