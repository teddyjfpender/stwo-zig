from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_build_lib.aot_pack import (  # noqa: E402
    AotPackError,
    write_aot_carriers,
    write_aot_pack,
)


NATIVE = ROOT / "src/backends/cuda/native"


class CudaAotAuthenticationTests(unittest.TestCase):
    def test_carrier_rejects_malformed_or_tampered_cubin_digest(self) -> None:
        payload = b"authenticated-cubin"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cubin = root / "test.cubin"
            cubin.write_bytes(payload)
            entry: dict[str, object] = {
                "cache_key": 5,
                "sm": 90,
                "abi_schema": 1,
                "kernel_name": "test_kernel",
                "cubin": cubin,
            }
            pack = root / "pack.bin"
            write_aot_pack([entry], pack)
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(),
                entry["sha256"],
            )
            _, lookup = write_aot_carriers([dict(entry)], pack, root)
            source = lookup.read_text(encoding="utf-8")
            self.assertIn("std::uint8_t sha256[32]", source)
            self.assertIn("0x0e, 0x71", source)
            compiler = shutil.which("c++")
            if compiler is not None:
                subprocess.run(
                    [
                        compiler,
                        "-std=c++17",
                        "-c",
                        str(lookup),
                        "-o",
                        str(root / "lookup.o"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

            for malformed in (None, "0" * 63, "A" * 64, "g" * 64):
                changed = dict(entry)
                changed["sha256"] = malformed
                with self.subTest(digest=malformed):
                    with self.assertRaisesRegex(
                        AotPackError,
                        "malformed cubin SHA-256",
                    ):
                        write_aot_carriers([changed], pack, root)

            pack.write_bytes(b"X" + payload[1:])
            with self.assertRaisesRegex(
                AotPackError,
                "digest disagrees with the pack",
            ):
                write_aot_carriers([dict(entry)], pack, root)

    def test_embedded_sha256_matches_standard_vectors(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        harness = r"""
#include "aot_sha256.h"

#include <cassert>
#include <cstddef>
#include <cstring>

static void check(
    const unsigned char *payload,
    std::size_t size,
    const unsigned char expected[32]) {
    unsigned char observed[32] = {};
    assert(stwo_cuda_aot::sha256(payload, size, observed));
    assert(stwo_cuda_aot::digest_equal(expected, observed));
}

int main() {
    const unsigned char empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    const unsigned char abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const unsigned char long_message[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    const char *long_payload =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check(nullptr, 0, empty);
    check(reinterpret_cast<const unsigned char *>("abc"), 3, abc);
    check(
        reinterpret_cast<const unsigned char *>(long_payload),
        std::strlen(long_payload),
        long_message);
}
"""
        self._compile_and_run(compiler, harness, ())

    def test_loader_authenticates_before_cuda_module_load(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        digest = hashlib.sha256(b"cbin").digest()
        digest_values = ", ".join(f"0x{value:02x}" for value in digest)
        harness = f"""
#include "aot_loader.h"
#include <cuda.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

static unsigned char kImage[4] = {{'c', 'b', 'i', 'n'}};
static const unsigned char kExpected[32] = {{{digest_values}}};
static int kModuleLoads = 0;
static unsigned char kContext = 0;
static unsigned char kStream = 0;
static unsigned char kModule = 0;
static unsigned char kFunction = 0;

extern "C" bool stwo_aot_lookup(
    std::uint64_t cache_key,
    std::uint32_t sm_major,
    std::uint32_t sm_minor,
    std::uint32_t abi_schema,
    const char *kernel_name,
    const unsigned char **out_data,
    std::size_t *out_len,
    unsigned char out_sha256[32]) {{
    if (cache_key != 5 || sm_major != 9 || sm_minor != 0 ||
        abi_schema != 1 || std::strcmp(kernel_name, "test_kernel") != 0) {{
        return false;
    }}
    *out_data = kImage;
    *out_len = sizeof(kImage);
    std::memcpy(out_sha256, kExpected, sizeof(kExpected));
    return true;
}}

extern "C" int stwo_exec_context_stream(void *, void **out) {{
    *out = &kStream;
    return CUDA_SUCCESS;
}}
extern "C" int stwo_exec_context_device(void *, int *out) {{
    *out = 0;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuCtxGetCurrent(CUcontext *out) {{
    *out = &kContext;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuCtxGetDevice(CUdevice *out) {{
    *out = 0;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuDeviceGetAttribute(int *out, int attribute, CUdevice) {{
    *out = attribute == CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR ? 9 : 0;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuModuleLoadData(CUmodule *out, const void *) {{
    ++kModuleLoads;
    *out = &kModule;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuModuleGetFunction(
    CUfunction *out,
    CUmodule,
    const char *) {{
    *out = &kFunction;
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuModuleUnload(CUmodule) {{ return CUDA_SUCCESS; }}
extern "C" CUresult cuFuncGetAttribute(
    int *out,
    int attribute,
    CUfunction) {{
    switch (attribute) {{
        case CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK: *out = 1024; break;
        case CU_FUNC_ATTRIBUTE_NUM_REGS: *out = 32; break;
        case CU_FUNC_ATTRIBUTE_BINARY_VERSION: *out = 90; break;
        case CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES: *out = 49152; break;
        case CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES: *out = 96; break;
        case CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES: *out = 128; break;
        default: return CUDA_ERROR_INVALID_VALUE;
    }}
    return CUDA_SUCCESS;
}}
extern "C" CUresult cuLaunchKernel(
    CUfunction,
    unsigned, unsigned, unsigned,
    unsigned, unsigned, unsigned,
    unsigned, CUstream, void **, void **) {{
    return CUDA_SUCCESS;
}}

int main() {{
    int exec_context = 0;
    void *loader = nullptr;
    assert(stwo_native_aot_loader_create(&exec_context, &loader) == CUDA_SUCCESS);
    const std::uint32_t grid[3] = {{1, 1, 1}};
    const std::uint32_t block[3] = {{32, 1, 1}};
    void *function = nullptr;
    StwoNativeAotFunctionReceipt receipt{{}};
    assert(stwo_native_aot_function_bind(
        loader, 5, 1, "test_kernel", grid, block, 0, 1,
        &function, &receipt) == CUDA_SUCCESS);
    assert(kModuleLoads == 1);
    assert(receipt.abi_version == 3);
    assert(receipt.local_bytes == 96);
    assert(receipt.static_shared_bytes == 128);
    assert(receipt.verification.abi_version == 1);
    assert(receipt.verification.verified == 1);
    assert(receipt.verification.cubin_bytes == sizeof(kImage));
    assert(std::memcmp(
        receipt.verification.expected_sha256,
        receipt.verification.observed_sha256,
        32) == 0);
    assert(stwo_native_aot_function_destroy(function) == CUDA_SUCCESS);
    function = nullptr;
    StwoNativeAotFunctionReceipt cached_receipt{{}};
    assert(stwo_native_aot_function_bind(
        loader, 5, 1, "test_kernel", grid, block, 0, 1,
        &function, &cached_receipt) == CUDA_SUCCESS);
    assert(kModuleLoads == 1);
    assert(cached_receipt.verification.verified == 1);
    assert(std::memcmp(
        receipt.verification.observed_sha256,
        cached_receipt.verification.observed_sha256,
        32) == 0);
    assert(stwo_native_aot_function_destroy(function) == CUDA_SUCCESS);
    assert(stwo_native_aot_loader_destroy(loader) == CUDA_SUCCESS);

    kImage[0] ^= 0xff;
    loader = nullptr;
    function = nullptr;
    assert(stwo_native_aot_loader_create(&exec_context, &loader) == CUDA_SUCCESS);
    assert(stwo_native_aot_function_bind(
        loader, 5, 1, "test_kernel", grid, block, 0, 1,
        &function, &receipt) == CUDA_ERROR_INVALID_IMAGE);
    assert(function == nullptr);
    assert(kModuleLoads == 1);
    assert(stwo_native_aot_loader_destroy(loader) == CUDA_SUCCESS);
}}
"""
        fake_cuda = r"""
#ifndef CUDA_H
#define CUDA_H

typedef void *CUcontext;
typedef void *CUstream;
typedef void *CUmodule;
typedef void *CUfunction;
typedef int CUdevice;
typedef int CUresult;

enum {
    CUDA_SUCCESS = 0,
    CUDA_ERROR_INVALID_VALUE = 1,
    CUDA_ERROR_OUT_OF_MEMORY = 2,
    CUDA_ERROR_INVALID_IMAGE = 200,
    CUDA_ERROR_INVALID_CONTEXT = 201,
    CUDA_ERROR_INVALID_HANDLE = 400,
    CUDA_ERROR_NOT_FOUND = 500,
    CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75,
    CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76,
    CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 0,
    CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES = 1,
    CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES = 3,
    CU_FUNC_ATTRIBUTE_NUM_REGS = 4,
    CU_FUNC_ATTRIBUTE_BINARY_VERSION = 6,
    CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES = 8,
};

#ifdef __cplusplus
extern "C" {
#endif
CUresult cuCtxGetCurrent(CUcontext *);
CUresult cuCtxGetDevice(CUdevice *);
CUresult cuDeviceGetAttribute(int *, int, CUdevice);
CUresult cuModuleLoadData(CUmodule *, const void *);
CUresult cuModuleGetFunction(CUfunction *, CUmodule, const char *);
CUresult cuModuleUnload(CUmodule);
CUresult cuFuncGetAttribute(int *, int, CUfunction);
CUresult cuLaunchKernel(
    CUfunction,
    unsigned, unsigned, unsigned,
    unsigned, unsigned, unsigned,
    unsigned, CUstream, void **, void **);
#ifdef __cplusplus
}
#endif

#endif
"""
        self._compile_and_run(
            compiler,
            harness,
            (NATIVE / "aot_loader.cpp",),
            fake_cuda=fake_cuda,
        )

    def _compile_and_run(
        self,
        compiler: str,
        harness: str,
        sources: tuple[Path, ...],
        *,
        fake_cuda: str | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "aot_authentication_test.cpp"
            executable = root / "aot_authentication_test"
            harness_path.write_text(textwrap.dedent(harness), encoding="utf-8")
            if fake_cuda is not None:
                (root / "cuda.h").write_text(
                    textwrap.dedent(fake_cuda),
                    encoding="utf-8",
                )
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O2",
                    "-pthread",
                    "-I",
                    str(root),
                    "-I",
                    str(NATIVE),
                    str(harness_path),
                    *(str(source) for source in sources),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
