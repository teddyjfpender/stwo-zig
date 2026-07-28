//! Concrete exact Blake interaction authority over one proof transaction.

const exact_aot = @import("stwo_cuda_backend").runtime.interactions.blake_exact;
const completion = @import("stwo_cuda_backend").runtime.stages.relation_completion;
const completion_bindings = @import("completion_bindings.zig");
const completion_plan = @import("completion_plan.zig");
const facades = @import("facades.zig");
const interaction_ingress = @import("interaction_ingress.zig");
const interaction_plan = @import("interaction_plan.zig");
const slots = @import("slots.zig");

pub const abi_schema = @import("stwo_cuda_backend").abi.schema.KernelSchema.native_blake_exact_interaction_v1;
pub const cache_key = exact_aot.cache_key;
pub const kernel_name = exact_aot.kernel_name;
pub const program_identity = exact_aot.program_identity;

pub fn generate(
    transaction: anytype,
    invocation: facades.Invocation,
) !void {
    try validateInvocation(invocation);
    const bound = try completion_bindings.bind(
        transaction,
        invocation.geometry,
        invocation.views,
    );
    var components: [exact_aot.component_count]exact_aot.Component = undefined;
    for (&components, bound.resident.components) |*output, component| {
        output.* = .{
            .log_rows = component.log_rows,
            .main = component.main,
            .preprocessed = component.preprocessed,
            .interaction = component.interaction,
            .denominators = component.denominators,
        };
    }
    try exact_aot.generate(
        transaction.proofSession(),
        .{
            .relation_elements = bound.resident.relation_elements,
            .components = components,
        },
        invocation.geometry.statement.log_n_rows,
    );

    const interaction = try interaction_plan.Plan.init(
        invocation.geometry,
        invocation.views,
    );
    var policy = try completion_plan.Plan.init(interaction);
    const instances = try bound.instances();
    const prepared = try completion.prepare(
        transaction.allocator,
        .{
            .topology = policy.topology(),
            .buffers = bound.buffers,
            .instances = &instances,
        },
    );
    defer completion.deinit(transaction.allocator, prepared);
    try completion.Native.execute(transaction.proofSession(), prepared);
}

pub fn AuthorityFor(comptime Transaction: type) type {
    return struct {
        pub fn facade(transaction: *Transaction) facades.Interaction {
            return .{
                .version = facades.abi_version,
                .identity = program_identity,
                .context = transaction,
                .prepare_ingress = ingressCallback,
                .generate_interaction = generateCallback,
            };
        }

        pub fn uploadGraph(
            transaction: *Transaction,
            invocation: facades.Invocation,
        ) !void {
            try interaction_ingress.upload(transaction, invocation);
        }

        fn ingressCallback(
            context: *anyopaque,
            invocation: facades.Invocation,
        ) anyerror!void {
            const transaction: *Transaction = @ptrCast(@alignCast(context));
            try uploadGraph(transaction, invocation);
        }

        fn generateCallback(
            context: *anyopaque,
            invocation: facades.Invocation,
        ) anyerror!void {
            const transaction: *Transaction = @ptrCast(@alignCast(context));
            try generate(transaction, invocation);
        }
    };
}

fn validateInvocation(invocation: facades.Invocation) !void {
    if (invocation.interaction_slot != slots.interaction_evaluations or
        invocation.interaction_denominators_slot !=
            slots.interaction_denominators or
        invocation.statement1_claims_slot != slots.statement1_claims)
    {
        return error.InvalidKernelDescriptor;
    }
    try invocation.views.validate(invocation.geometry);
}

test "exact interaction facade identity is the authenticated AOT closure" {
    const std = @import("std");
    const FakeTransaction = struct {};
    var transaction = FakeTransaction{};
    const facade = AuthorityFor(FakeTransaction).facade(&transaction);
    try facade.validate();
    try std.testing.expectEqualSlices(
        u8,
        &program_identity,
        &facade.identity,
    );
    try std.testing.expectEqual(
        abi_schema,
        @import("stwo_cuda_backend").abi.schema.KernelSchema.native_blake_exact_interaction_v1,
    );
}
