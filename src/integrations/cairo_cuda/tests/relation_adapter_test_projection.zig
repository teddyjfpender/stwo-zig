//! projection cases; fixture authority is shared with the other test owners.
const std = @import("std");
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const adapter = @import("../relation_adapter.zig");

const Support = @import("relation_adapter_test_support.zig");
const Fixture = Support.Fixture;
const DeviceFixture = Support.DeviceFixture;
const UploadRecorder = Support.UploadRecorder;

test "relation adapter fails closed on order descriptor and coverage drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    std.mem.swap(
        u32,
        &fixture.proof.canonical_order[0],
        &fixture.proof.canonical_order[1],
    );
    try std.testing.expectError(
        adapter.Error.InvalidComponentOrder,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    std.mem.swap(
        u32,
        &fixture.proof.canonical_order[0],
        &fixture.proof.canonical_order[1],
    );

    const add = fixture.relations.find("add_opcode") orelse
        return error.MissingTemplate;
    add.traces[0].descriptors[15] = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    add.traces[0].descriptors[15] = 0;

    const memory = fixture.relations.find("memory_id_to_big") orelse
        return error.MissingTemplate;
    const saved_part = memory.traces[1].part;
    memory.traces[1].part = .component;
    try std.testing.expectError(
        adapter.Error.InvalidRelationTrace,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    memory.traces[1].part = saved_part;

    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var uploader = UploadRecorder{};
    try std.testing.expectError(
        adapter.Error.InvalidPreparedInputShape,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            std.mem.zeroes(
                @import("stwo_cuda_backend").runtime.stages.relation.DeviceBuffers,
            ),
            &.{},
        ),
    );
}

test "SN2 canonical CUDA ingress derives every device table" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var device = try DeviceFixture.init(std.testing.allocator, &plan);
    defer device.deinit();
    var uploader = UploadRecorder{};

    const prepared = try plan.prepareAndUpload(
        std.testing.allocator,
        &uploader,
        device.buffers,
        device.instances,
    );
    defer relation_stage.deinit(std.testing.allocator, prepared);

    try std.testing.expectEqual(@as(u32, 180), uploader.calls);
    try std.testing.expectEqual(
        plan.descriptor_storage.len,
        uploader.descriptor_records,
    );
    try std.testing.expectEqual(
        plan.geometry.len,
        uploader.geometry_records,
    );
    try std.testing.expectEqual(
        device.source_storage[0].address,
        uploader.first_pointer,
    );
    try std.testing.expectEqualSlices(
        u8,
        &plan.topology_identity,
        &relation_stage.topologyIdentity(prepared),
    );
}

test "SN2 canonical CUDA ingress rejects lookup undersize and tail alias" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var device = try DeviceFixture.init(std.testing.allocator, &plan);
    defer device.deinit();
    var uploader = UploadRecorder{};

    const source_length = device.source_storage[0].len;
    device.source_storage[0].len = plan.instances[0].geometry.rows;
    try std.testing.expect(device.source_storage[0].len < source_length);
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            device.buffers,
            device.instances,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), uploader.calls);

    device.source_storage[0].len = source_length;
    device.output_storage[0].address =
        device.source_storage[0].address +
        @as(usize, plan.instances[0].geometry.rows) * @sizeOf(u32);
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            device.buffers,
            device.instances,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), uploader.calls);
}

test "relation adapter enforces Rust layout-domain bounds" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const memory_address = fixture.relations.find(
        "memory_address_to_id",
    ) orelse return error.MissingTemplate;
    const saved_chunks = memory_address.traces[0].layout_arg;
    memory_address.traces[0].layout_arg = 2048;
    try std.testing.expectError(
        adapter.Error.InvalidProofGeometry,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    memory_address.traces[0].layout_arg = saved_chunks;

    const xor = fixture.proof.find("verify_bitwise_xor_12") orelse
        return error.MissingRelationComponent;
    const xor_parts: []proof_plan.TracePart = @constCast(xor.trace_parts);
    const saved_rows = xor_parts[0].rows;
    xor_parts[0].rows = .{
        .real_rows = 1 << 19,
        .padded_rows = 1 << 19,
    };
    try std.testing.expectError(
        adapter.Error.InvalidProofGeometry,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    xor_parts[0].rows = saved_rows;
}
