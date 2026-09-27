//! Genuine one-leaf exact outer proof for the joined complete-bundle gate.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("block_v5_global_receiver_v1.zig");
const Programs = @import("block_v5_program_native_batch_receiver_v3.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Admission = @import("block_v5_native_recursive_admission_v3.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Producer = @import("../recursion/blake3_native_parent_producer.zig");
const Bus = @import("../recursion/block_v5_recursive_public_bus_v1.zig");
const Leaf = @import("../recursion/block_v5_reusable_native_leaf_v1.zig");
const LeafProtocol = @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
const OuterProtocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const OuterBus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const Frames = @import("../recursion/block_v5_open_child_frames_v2.zig");
const OuterPreparation = @import("../recursion/block_v5_open_parent_preparation_v2.zig");
const Exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const Stage = @import("block_v5_open_forest_stage_v1.zig");
const Manifest = @import("block_v5_open_forest_manifest_v1.zig");

pub const Fixture = struct {
    a: std.mem.Allocator,
    leaf_pins: [1]Global.RecursiveLeafPin,
    leaf_schedule: []Bus.Wire,
    outer_key: OuterProtocol.Key,
    outer_id: [32]u8,
    outer_schedule: []OuterBus.Wire,
    leaf_bytes: []u8,
    bytes: []u8,
    public_pins: Exact.OuterPins,
    native_open_sum: core.fields.qm31.QM31,

    pub fn init(a: std.mem.Allocator, pin: Programs.InstancePin, capture: *const Native.VerifiedCapture, sealed: Seal.Sealed, source_pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Fixture {
        const profile: LeafProtocol.Profile = if (std.meta.eql(source_pins.config, LeafProtocol.Profile.diagnostic_q8_pow0.config()))
            .diagnostic_q8_pow0
        else if (std.meta.eql(source_pins.config, LeafProtocol.Profile.csp_q70_pow26.config()))
            .csp_q70_pow26
        else
            return error.UnsupportedCompleteFixtureSecurity;
        var admission = try Admission.Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, 0, sealed, source_pins, entries, catalog);
        defer admission.deinit();
        var leaf_prepared = try Bus.prepare(a, &admission, capture, 2);
        defer leaf_prepared.deinit();
        const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &leaf_prepared.recursive, profile);
        const leaf_key = try LeafProtocol.Key.fromGeometry(geometry, leaf_prepared.wires);
        const leaf_id = try leaf_key.identity();
        const leaf_schedule = try a.dupe(Bus.Wire, leaf_prepared.wires);
        errdefer a.free(leaf_schedule);
        const leaf_authority = try LeafProtocol.Admission.init(leaf_key, leaf_id, leaf_schedule, leaf_prepared.values);
        const leaf_plan = try Producer.PlanForProtocol(Cpu, LeafProtocol).init(a, &leaf_prepared.recursive.rows, leaf_authority);
        defer leaf_plan.deinit();
        var leaf_artifact = try leaf_plan.prove(a, &leaf_prepared.recursive.rows);
        defer leaf_artifact.deinit();
        const leaf_bytes = try Parent.codec.encode(a, &leaf_artifact, &leaf_authority);
        errdefer a.free(leaf_bytes);
        var leaf_verified = try Leaf.verify(a, leaf_bytes, leaf_key, leaf_id, leaf_schedule, &admission, capture.receipt);
        defer leaf_verified.deinit();
        var child = try Frames.fromNative(a, &admission, capture.receipt, leaf_key, leaf_id, leaf_schedule);
        defer child.deinit();
        var outer_prepared = try OuterPreparation.prepare(a, .exact_outer, &.{child}, &.{&leaf_verified.equation}, 2);
        defer outer_prepared.deinit();
        const outer_geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &outer_prepared.recursive, profile);
        const outer_key = try OuterProtocol.Key.fromGeometry(outer_geometry, outer_prepared.wires);
        const outer_id = try outer_key.identity();
        const outer_schedule = try a.dupe(OuterBus.Wire, outer_prepared.wires);
        errdefer a.free(outer_schedule);
        const outer_authority = try OuterProtocol.Admission.init(outer_key, outer_id, outer_schedule, outer_prepared.values);
        const outer_plan = try Producer.PlanForProtocol(Cpu, OuterProtocol).init(a, &outer_prepared.recursive.rows, outer_authority);
        defer outer_plan.deinit();
        var artifact = try outer_plan.prove(a, &outer_prepared.recursive.rows);
        defer artifact.deinit();
        const bytes = try Parent.codec.encode(a, &artifact, &outer_authority);
        const span = child.span;
        return .{ .a = a, .leaf_pins = .{.{ .key = leaf_key, .expected_id = leaf_id, .schedule = leaf_schedule }}, .leaf_schedule = leaf_schedule, .outer_key = outer_key, .outer_id = outer_id, .outer_schedule = outer_schedule, .leaf_bytes = leaf_bytes, .bytes = bytes, .native_open_sum = capture.receipt.open_sum, .public_pins = .{
            .job_id = span.job_id,
            .source_image_digest = span.source_image_digest,
            .sealed_digest = span.sealed_digest,
            .segment_count = span.segment_count,
            .first_cycle = span.first_cycle,
            .last_cycle = span.last_cycle,
            .initial_pc = span.initial_pc,
            .final_pc = span.final_pc,
        } };
    }
    pub fn deinit(self: *Fixture) void {
        self.a.free(self.bytes);
        self.a.free(self.leaf_bytes);
        self.a.free(self.outer_schedule);
        self.a.free(self.leaf_schedule);
        self.* = undefined;
    }
    pub fn pins(self: *const Fixture) Global.RecursivePins {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.bytes, &hash, .{});
        return .{ .leaves = &self.leaf_pins, .parents = &.{}, .outer = .{ .key = self.outer_key, .expected_id = self.outer_id, .schedule = self.outer_schedule }, .file = .{ .byte_len = self.bytes.len, .sha256 = hash } };
    }
    pub const Loader = struct {
        fixture: *const Fixture,
        pub fn load(self: @This(), a: std.mem.Allocator) ![]u8 {
            return a.dupe(u8, self.fixture.bytes);
        }
    };
    pub fn loader(self: *const Fixture) Loader {
        return .{ .fixture = self };
    }
    pub fn writeDetached(self: *const Fixture, dir: std.fs.Dir) !Global.DetachedForest {
        const limits = Manifest.Limits{ .max_execution_count = 1, .max_manifest_bytes = 4 * 1024 * 1024, .max_proof_bytes = 32 * 1024 * 1024 };
        var buffer: [80]u8 = undefined;
        const leaf_file = try Stage.writeProof(dir, try Stage.leafPath(0, &buffer), self.leaf_bytes, limits.max_proof_bytes);
        const outer_file = try Stage.writeProof(dir, Stage.OUTER_FILE, self.bytes, limits.max_proof_bytes);
        const hash = try Manifest.writeWire(self.a, dir, .{
            .version = Manifest.VERSION,
            .profile = self.outer_key.profile,
            .execution_count = 1,
            .leaf_files = &.{leaf_file},
            .parents = &.{},
            .outer = .{ .node = self.pins().outer, .file = outer_file },
            .public_pins = self.public_pins,
            .combined_native_open_sum = self.native_open_sum,
        }, limits);
        return .{ .dir = dir, .manifest_sha256 = hash, .limits = limits };
    }
};
