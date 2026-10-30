from starkware.cairo.common.registers import get_label_location
from ethereum.prague.vm.precompiled_contracts.mapping import precompile_table_lookup
from op_stack.p256_precompile import p256_verify

func lookup{range_check_ptr}(address: felt) -> (felt, felt) {
    if (address == 2 ** 144) {
        let (function) = get_label_location(p256_verify);
        return (address, cast(function, felt));
    }
    return precompile_table_lookup(address);
}
