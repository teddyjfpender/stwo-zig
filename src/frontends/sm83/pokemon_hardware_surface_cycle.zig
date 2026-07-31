const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const unsupported = @import("pokemon_hardware_surface_inventory.zig");

const Access = runner.cartridge_memory.Access;

pub fn access(result: machine.CartridgeStepResult, cycle: usize) ?Access {
    if (result.instruction) |instruction|
        return instruction.activeAccesses()[cycle];
    if (result.event == .interrupt_service)
        return result.service.activeCycles()[cycle].access;
    return null;
}

pub fn origin(
    result: machine.CartridgeStepResult,
    cycle: usize,
) unsupported.Origin {
    if (result.instruction != null) return .instruction;
    if (result.event == .interrupt_service and
        result.service.activeCycles()[cycle].kind == .oam_bug)
    {
        return .interrupt_service_oam_bug;
    }
    return .other;
}

pub fn advanceDma(
    before: runner.dma.State,
    maybe_access: ?Access,
) !runner.dma.Transition {
    const write_page: ?u8 = if (maybe_access) |item|
        if (item.logical_address == runner.dma.DMA_ADDRESS and
            item.action == .write)
            item.value
        else
            null
    else
        null;
    const event: runner.dma.Event = if (before.phase == .transfer)
        if (write_page) |page|
            .{ .transfer_and_write = .{
                .source_byte = 0,
                .page = page,
            } }
        else
            .{ .transfer = 0 }
    else if (write_page) |page|
        .{ .write_ff46 = page }
    else
        .tick;
    return runner.dma.Transition.apply(before, event);
}
