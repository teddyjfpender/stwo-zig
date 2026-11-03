#include "rv64/pcs_native.h"
#include <cstdio>
#include <stdexcept>
#include <array>
static int run(void*,uint64_t,void*raw){void*s=raw;uint32_t a[8]={1},b[8]={2};StwoRv64GpuLease x{},y{},bad{};if(stwo_rv64_gpu_lease_allocate(s,32,1,a,&x)||stwo_rv64_gpu_lease_validate(s,&x,a))return 1;std::puts("PASS diagnostic forwarded allocation+exactscope");if(stwo_rv64_gpu_lease_allocate(s,64,2,a,&y)||stwo_rv64_gpu_lease_rebind(s,&y,a,b)||!stwo_rv64_gpu_lease_validate(s,&y,a)||stwo_rv64_gpu_lease_validate(s,&y,b))return 2;std::puts("PASS diagnostic forwarded scopepromotion+oldscope rejection");if(!stwo_rv64_gpu_lease_allocate(s,1u<<20,0,b,&bad))return 3;if(stwo_rv64_gpu_lease_release(s,&x)||stwo_rv64_gpu_lease_release(s,&y))return 4;uint64_t counts[5]={},bytes=0;if(stwo_rv64_gpu_session_live_leases(s,counts,&bytes)||bytes)return 5;for(auto c:counts)if(c)return 6;std::puts("PASS diagnostic capfailure+nativeallleasesreleased");return 0;}
int main(){void*s=nullptr;if(stwo_rv64_pcs_native_create(0,1u<<20,&s))return 1;int result=stwo_rv64_gpu_session_submit(s,run,s);stwo_rv64_pcs_native_destroy(s);return result;}
