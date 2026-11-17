"""Independent SHA-256 compression via OpenSSL 3's public SHA256_Transform ABI.

The producer's Zig service and the guest's Rust implementation are not used.
SHA256_CTX follows the installed OpenSSL 3 openssl/sha.h (112 bytes). This is
host-only oracle code; no dynamic library or hint is part of guest execution.
"""

import ctypes as C
from ctypes.util import find_library


class Context(C.Structure):
    _fields_ = [
        ("h", C.c_uint32 * 8),
        ("Nl", C.c_uint32),
        ("Nh", C.c_uint32),
        ("data", C.c_uint32 * 16),
        ("num", C.c_uint),
        ("md_len", C.c_uint),
    ]


class Compressor:
    def __init__(self):
        library = find_library("crypto")
        if library is None or C.sizeof(Context) != 112:
            raise ValueError(
                "SHA oracle requires OpenSSL 3 with the public SHA256_CTX ABI"
            )
        self.lib = C.CDLL(library)
        self.lib.OpenSSL_version_num.restype = C.c_ulong
        if self.lib.OpenSSL_version_num() >> 28 != 3:
            raise ValueError("SHA oracle requires OpenSSL major version 3")
        self.lib.OpenSSL_version.argtypes = [C.c_int]
        self.lib.OpenSSL_version.restype = C.c_char_p
        self.version = self.lib.OpenSSL_version(0).decode("ascii")
        self.lib.SHA256_Init.argtypes = [C.POINTER(Context)]
        self.lib.SHA256_Init.restype = C.c_int
        self.lib.SHA256_Transform.argtypes = [C.POINTER(Context), C.POINTER(C.c_ubyte)]
        self.lib.SHA256_Transform.restype = None

    def compress(self, state, block):
        if (
            len(state) != 8
            or any(not 0 <= word < 1 << 32 for word in state)
            or len(block) != 64
        ):
            raise ValueError("invalid SHA compression input")
        ctx = Context()
        if self.lib.SHA256_Init(C.byref(ctx)) != 1:
            raise ValueError("OpenSSL SHA initialization failed")
        ctx.h[:] = state
        data = (C.c_ubyte * 64).from_buffer_copy(block)
        self.lib.SHA256_Transform(C.byref(ctx), data)
        return tuple(ctx.h)
