test {
    _ = @import("runner/cartridge_memory_apu_test.zig");
    _ = @import("runner/cartridge_memory_core_test.zig");
    _ = @import("air/cartridge_access.zig");
    _ = @import("air/cartridge_access_test.zig");
    _ = @import("air/cartridge_access_component.zig");
    _ = @import("air/cartridge_access_component_test.zig");
    _ = @import("air/cartridge_machine_access.zig");
    _ = @import("air/cartridge_machine_access_test.zig");
    _ = @import("air/cartridge_memory_lookup.zig");
    _ = @import("air/cartridge_memory_lookup_component.zig");
    _ = @import("air/cartridge_memory_lookup_component_test.zig");
    _ = @import("air/cartridge_memory_lookup_test.zig");
    _ = @import("air/cartridge_rom_lookup.zig");
    _ = @import("air/cartridge_rom_lookup_component.zig");
    _ = @import("air/dma.zig");
    _ = @import("air/dma_component.zig");
    _ = @import("runner/dma.zig");
}
