# Delegation AIR ownership

This directory owns the existing independently sized DIV/REM, MUL, Keccak and
secp256k1 AIR providers and their family-local bridges, row formatters and native
interaction kernels. Each family keeps its concrete public module and layout.
`main_storage.zig` is the shared allocation/span validation helper; generic range
providers, CPU control, RAM policy and proof orchestration remain outside this
directory because they serve more than one delegation family.

`rv64_air.delegations` is the physical module owner. Existing
`rv64_air.arithmetic.{division,multiplication}` and
`rv64_air.crypto.{keccak,secp256k1,main_storage}` are compatibility aliases to the
same imported modules and preserve type identity. This relocation changes no
polynomial, committed layout, transcript framing, native arithmetic or runtime
admission policy.

`registry.zig` inventories implemented geometry using each layout's actual
constants. Its arithmetic dispatch walks the actual immutable opcode lists:
MUL is raw 49..52/57, DIV/REM is raw 53..56/58..61. These are interleaved ISA
opcode coordinates, not hypothetical contiguous FUNCTION ranges beginning at
48 or64. Registry membership is not an accepting proof API: caller admission,
unit/multiplicity bounds and physical claim closure still belong to the concrete
receiving protocol.

The Keccak quartet component remains explicitly experimental and inactive,
exactly as before the move. The registry reports the existing ordinary Keccak
layout; selecting the quartet requires its separate explicit component API.
There are no future-family placeholders or fallback providers.
