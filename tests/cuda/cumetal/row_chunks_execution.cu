#include <cuda_runtime.h>
#include <cstdio>
#include <vector>
#include STWO_ROW_PARITY_SOURCE
#include STWO_ROW_PARITY_FIXTURES

// Populate pointer tables on the device so translated providers use their
// device address representation; do not copy host pointer encodings into them.
__global__ void initialize_row_pointers(unsigned* input,unsigned* columns,unsigned* counts,
    unsigned** input_ptrs,unsigned** column_ptrs,unsigned** count_ptrs,unsigned rows) {
    for (unsigned i=0;i<6;++i) input_ptrs[i]=input+i*rows;
    for (unsigned i=0;i<281;++i) column_ptrs[i]=columns+i*rows;
    count_ptrs[0]=counts;
}

int main() {
    constexpr unsigned rows = kRowCount;
    unsigned *input, *columns, *lookup, *sub, *counts;
    unsigned **input_ptrs, **column_ptrs, **count_ptrs;
    if (cudaMalloc((void**)&input, sizeof(kRowInputs)) != cudaSuccess ||
        cudaMalloc((void**)&columns, sizeof(kRowExpected)) != cudaSuccess ||
        cudaMalloc((void**)&lookup, sizeof(kRowLookup)) != cudaSuccess ||
        cudaMalloc((void**)&sub, sizeof(kRowSub)) != cudaSuccess ||
        cudaMalloc((void**)&counts, sizeof(kRowCounts)) != cudaSuccess ||
        cudaMalloc((void**)&input_ptrs, 6*sizeof(unsigned*)) != cudaSuccess ||
        cudaMalloc((void**)&column_ptrs, 281*sizeof(unsigned*)) != cudaSuccess ||
        cudaMalloc((void**)&count_ptrs, sizeof(unsigned*)) != cudaSuccess) return 1;
    if (cudaMemcpy(input, kRowInputs, sizeof(kRowInputs), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemset(counts, 0, sizeof(kRowCounts)) != cudaSuccess) return 1;
    initialize_row_pointers<<<1,1>>>(input,columns,counts,input_ptrs,column_ptrs,count_ptrs,rows);
    if (cudaDeviceSynchronize()!=cudaSuccess) return 1;
    STWO_ROW_PARITY_KERNEL<<<1, 64>>>(input_ptrs, nullptr, nullptr, column_ptrs,
        count_ptrs, lookup, sub, rows);
    if (cudaDeviceSynchronize() != cudaSuccess) return 1;
    const unsigned* expected[]={kRowExpected,kRowLookup,kRowSub,kRowCounts};
    unsigned* device[]={columns,lookup,sub,counts};
    size_t sizes[]={sizeof(kRowExpected),sizeof(kRowLookup),sizeof(kRowSub),sizeof(kRowCounts)};
    for (unsigned bank=0; bank<4; ++bank) {
        std::vector<unsigned> observed(sizes[bank]/sizeof(unsigned));
        if (cudaMemcpy(observed.data(),device[bank],sizes[bank],cudaMemcpyDeviceToHost) != cudaSuccess) return 1;
        for (size_t i=0; i<observed.size(); ++i) if (observed[i]!=expected[bank][i]) {
            std::fprintf(stderr,"FAIL row chunks bank=%u index=%zu expected=%u actual=%u\n",bank,i,expected[bank][i],observed[i]);
            return 1;
        }
    }
    void* allocations[]={input,columns,lookup,sub,counts,input_ptrs,column_ptrs,count_ptrs};
    for (void* allocation:allocations) if (cudaFree(allocation)!=cudaSuccess) return 1;
    std::printf("PASS: row chunks match independent Python BLAKE G oracle\n");
    return 0;
}
