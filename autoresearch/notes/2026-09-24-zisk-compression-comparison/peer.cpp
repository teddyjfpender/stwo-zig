#include "blake3_core.hpp"
extern "C" void peer_compress(const uint32_t *cv, const uint32_t *block, uint64_t counter, uint8_t len, uint8_t flags, uint32_t *out) {
    blake3core::compress_xof(cv, block, len, counter, flags, out);
}
extern "C" void peer_batch(uint64_t n, uint32_t *sum) {
    uint32_t block[16], out[16];
    for (unsigned j=0;j<16;++j) { block[j]=j*0x1234567u; sum[j]=0; }
    for (uint64_t i=0;i<n;++i) {
        block[0]=(uint32_t)i;
        blake3core::compress_xof(blake3core::IV_host,block,64,0,11,out);
        for (unsigned j=0;j<16;++j) sum[j]^=out[j];
    }
}
