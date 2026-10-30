// Fjord/Jovian P256VERIFY: fixed 3450 gas, empty output on invalid signatures.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memset import memset
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from ethereum.prague.vm.evm_impl import Evm, EvmImpl
from ethereum.prague.vm.gas import charge_gas
from ethereum.exceptions import EthereumException
from ethereum_types.numeric import Uint
from ethereum_types.bytes import Bytes, BytesStruct
from op_stack.p256 import verify_signature

func p256_verify{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*, evm: Evm,
}() -> EthereumException* {
    alloc_locals;
    let err = charge_gas(Uint(3450));
    if (cast(err, felt) != 0) {
        return err;
    }
    local evm: Evm = evm;
    let valid = verify_signature(evm.value.message.value.data);
    if (valid == 0) {
        return cast(0, EthereumException*);
    }
    let (buffer) = alloc();
    memset(buffer, 0, 31);
    assert buffer[31] = 1;
    tempvar output = Bytes(new BytesStruct(buffer, 32));
    EvmImpl.set_output(output);
    return cast(0, EthereumException*);
}
