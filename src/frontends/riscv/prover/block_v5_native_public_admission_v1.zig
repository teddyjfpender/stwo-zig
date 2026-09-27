//! Native admission from a block job and machine endpoints, without per-leaf
//! program/memory Merkle schedules. Global providers prove those obligations.
const std = @import("std");
const core = @import("stwo_core");
const public = @import("../air/public_data.zig");
const seals = @import("block_v5_source_seal_v1.zig");
const Digest = [32]u8;
pub const Context = struct {
    job_id: Digest,
    source_image_digest: Digest,
    program_root: Digest,
    program_plan_digest: Digest,
    memory_plan_digest: Digest,
    initial_source_plan_digest: Digest,
    rw_endpoint_plan_digest: Digest,
    register_custody_mode: u32 = 0,
    register_endpoint_plan_digest: Digest = @splat(0),
    execution_index: u32,
    first_cycle: u64,
    last_cycle: u64,

    pub fn validate(self: Context) !void {
        if (self.register_custody_mode > 1 or (self.register_custody_mode == 1 and std.mem.allEqual(u8, &self.register_endpoint_plan_digest, 0))) return error.InvalidNativeV5RegisterContext;
        for ([_]Digest{ self.job_id, self.source_image_digest, self.program_root, self.program_plan_digest, self.memory_plan_digest, self.initial_source_plan_digest }) |digest|
            if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidNativeV5PublicContext;
        if (self.first_cycle == 0 or self.last_cycle < self.first_cycle)
            return error.InvalidNativeV5PublicSpan;
    }
    pub fn require(self: Context, pins: seals.Pins) !void {
        try self.validate();
        if (self.execution_index >= pins.counts[@intFromEnum(seals.Family.execution) - 1] or
            self.register_custody_mode != pins.register_custody_mode or
            (self.register_custody_mode == 1 and !std.meta.eql(self.register_endpoint_plan_digest, pins.register_endpoint_plan_digest)) or
            !std.meta.eql(self.job_id, pins.job_id) or
            !std.meta.eql(self.source_image_digest, pins.source_image_digest) or
            !std.meta.eql(self.program_root, pins.program_root) or
            !std.meta.eql(self.program_plan_digest, pins.program_plan_digest) or
            !std.meta.eql(self.memory_plan_digest, pins.memory_plan_digest) or
            !std.meta.eql(self.initial_source_plan_digest, pins.initial_source_plan_digest) or
            !std.meta.eql(self.rw_endpoint_plan_digest, pins.rw_endpoint_plan_digest))
            return error.UntrustedNativeV5PublicContext;
    }
    fn mix(self: Context, channel: *core.proof_suites.Blake3.Channel) void {
        channel.mixU32s(&.{ 0x42355041, 1, self.execution_index }); // B5PA
        for ([_]Digest{ self.job_id, self.source_image_digest, self.program_root, self.program_plan_digest, self.memory_plan_digest, self.initial_source_plan_digest, self.rw_endpoint_plan_digest }) |digest| channel.mixRoot(digest);
        channel.mixU64(self.first_cycle);
        channel.mixU64(self.last_cycle);
        if (self.register_custody_mode == 1) {
            channel.mixU32s(&.{ 2, self.register_custody_mode });
            channel.mixRoot(self.register_endpoint_plan_digest);
        }
    }
};

pub const Admission = struct {
    context: Context,
    public_digest: Digest,
    expected_id: Digest,
    pub fn init(context: Context, data: *const public.Blake3PublicData) !Admission {
        try context.validate();
        try data.validate();
        const digest = publicDigest(data);
        const result = Admission{ .context = context, .public_digest = digest, .expected_id = identity(context, digest) };
        try result.validatePublic(data);
        return result;
    }
    pub fn validatePublic(self: Admission, data: *const public.Blake3PublicData) !void {
        try self.context.validate();
        try data.validate();
        const count = try std.math.add(u64, self.context.last_cycle - self.context.first_cycle, 1);
        if (count != data.clock or data.program_root == null or
            !std.meta.eql(data.program_root.?.bytes, self.context.program_root) or
            !std.meta.eql(self.public_digest, publicDigest(data)) or
            !std.meta.eql(self.expected_id, identity(self.context, self.public_digest)))
            return error.UntrustedNativeV5PublicAdmission;
    }
    pub fn require(self: Admission, pins: seals.Pins, data: *const public.Blake3PublicData) !void {
        try self.context.require(pins);
        try self.validatePublic(data);
    }
};

/// Pure public preimage identity; it does not admit an execution or proof.
pub fn publicDigest(data: *const public.Blake3PublicData) Digest {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42355044, 1 }); // B5PD
    data.mixInto(&channel);
    return channel.digestBytes();
}
fn identity(context: Context, digest: Digest) Digest {
    var channel = core.proof_suites.Blake3.Channel{};
    context.mix(&channel);
    channel.mixRoot(digest);
    return channel.digestBytes();
}
