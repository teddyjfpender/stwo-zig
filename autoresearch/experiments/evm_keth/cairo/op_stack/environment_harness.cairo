from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from ethereum.prague.blocks import Header
from ethereum.prague.vm.env_impl import BlockEnvironment
from ethereum.crypto.hash import Hash32
from op_stack.environment_binding import bind_environment

func bind{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, block_env: BlockEnvironment}(
    header: Header
) -> (Hash32, Hash32) {
    alloc_locals;
    local history: Header*;
    local n;
    %{
        from ethereum.prague.blocks import Header
        from utils.fixture_loader import LoadKethFixture
        loader = LoadKethFixture("Prague", "prague")
        ids.history = segments.gen_arg([gen_arg(Header, loader.json_to_header(h)) for h in program_input["headers"]])
        ids.n = len(program_input["headers"])
    %}
    let (keccak_ptr) = alloc();
    local start: felt* = keccak_ptr;
    let (hash, root) = bind_environment(block_env, header, history, n);
    local hash: Hash32 = hash;
    local root: Hash32 = root;
    finalize_keccak(start, keccak_ptr);
    return (hash, root);
}
