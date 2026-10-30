// Independent CPU sort oracle; production sorting and witnesses stay on GPU.
#include "../native/resident_parent_readonly_v1.cuh"
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <utility>
#include <vector>
#include <fstream>
#include <cstring>
static void check(cudaError_t e) { if (e != cudaSuccess) throw std::runtime_error(cudaGetErrorString(e)); }
struct Buffer { uint32_t *p=nullptr; explicit Buffer(size_t n) { check(cudaMalloc(&p,n*4)); } ~Buffer(){cudaFree(p);} };
static std::vector<std::vector<uint32_t>> original_rows;
static uint32_t physical(uint32_t row,uint32_t log){return original_rows.at(log).at(row);}
static uint32_t read_word(std::ifstream& f){unsigned char b[4];if(!f.read((char*)b,4))throw std::runtime_error("truncated original row oracle");return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);}
int main(int argc,char**argv) try {
    if(argc!=2)throw std::runtime_error("original Zig row-map oracle file required");
    std::ifstream maps(argv[1],std::ios::binary);char magic[8];if(!maps.read(magic,8)||std::memcmp(magic,"ROWM1\0\0\0",8))throw std::runtime_error("row oracle magic");
    uint32_t logs=read_word(maps);if(logs!=17)throw std::runtime_error("row oracle coverage");original_rows.resize(logs+1);
    for(uint32_t log=1;log<=logs;log++){uint32_t count=read_word(maps);if(count!=(1u<<log))throw std::runtime_error("row oracle geometry");auto& rows=original_rows[log];rows.resize(count);std::vector<bool> used(count);for(auto& row:rows){row=read_word(maps);if(row>=count||used[row])throw std::runtime_error("nonbijective original row map");used[row]=true;}}
    if(maps.peek()!=std::char_traits<char>::eof())throw std::runtime_error("row oracle tail");
    cudaStream_t stream;check(cudaStreamCreateWithFlags(&stream,cudaStreamNonBlocking));
    uint64_t checked_words=0,entries_total=0;unsigned cases=0,hostiles=0;
    for(uint32_t count : {1u,2u,3u,127u,512u,4099u,65536u}) {
        uint32_t log=1;while((1u<<log)<count)++log;uint32_t size=1u<<log;
        std::vector<uint32_t> main(5ull*size,0),in(count),out(count),args(4ull*count);
        std::vector<std::pair<uint32_t,uint32_t>> expected;
        for(uint32_t i=0;i<count;++i){
            in[i]=i;out[i]=(uint64_t)i*73%count;
            uint32_t key=i%5==0?0xffffffffu:(i%7==0?0u:(i*2654435761u)%4093u);
            uint32_t value=key%0x7fffffffu;
            const uint32_t at=physical(i,log);
            for(uint32_t c=0;c<4;++c)main[(size_t)c*size+at]=(key>>(8*c))&255;
            main[(size_t)4*size+at]=value;expected.emplace_back(key,value);
        }
        std::stable_sort(expected.begin(),expected.end(),[](auto a,auto b){return a.first<b.first;});
        Buffer rows(count),output_rows(count),source(main.size()),keys(count),values(count),sorted_keys(count),sorted_values(count),result(args.size()+16),status(1);
        size_t bytes=0;check(stwo_parent_readonly_temp_bytes_v1(count,&bytes));Buffer temp((bytes+3)/4);
        check(cudaMemcpyAsync(rows.p,in.data(),count*4,cudaMemcpyHostToDevice,stream));
        check(cudaMemcpyAsync(output_rows.p,out.data(),count*4,cudaMemcpyHostToDevice,stream));
        check(cudaMemcpyAsync(source.p,main.data(),main.size()*4,cudaMemcpyHostToDevice,stream));
        check(cudaMemsetAsync(result.p,0xa5,(args.size()+16)*4,stream));check(cudaMemsetAsync(status.p,0,4,stream));
        cudaEvent_t begin,end;check(cudaEventCreate(&begin));check(cudaEventCreate(&end));check(cudaEventRecord(begin,stream));
        check(stwo_parent_readonly_gather_v1(rows.p,count,source.p,log,keys.p,values.p,status.p,stream));
        check(stwo_parent_readonly_sort_v1(temp.p,bytes,keys.p,sorted_keys.p,values.p,sorted_values.p,count,stream));
        check(stwo_parent_readonly_arguments_v1(output_rows.p,count,sorted_keys.p,sorted_values.p,result.p,count,status.p,stream));
        check(cudaEventRecord(end,stream));check(cudaEventSynchronize(end));float milliseconds=0;check(cudaEventElapsedTime(&milliseconds,begin,end));
        uint32_t flag=99,tail[16];check(cudaMemcpyAsync(&flag,status.p,4,cudaMemcpyDeviceToHost,stream));
        check(cudaMemcpyAsync(args.data(),result.p,args.size()*4,cudaMemcpyDeviceToHost,stream));
        check(cudaMemcpyAsync(tail,result.p+args.size(),64,cudaMemcpyDeviceToHost,stream));check(cudaStreamSynchronize(stream));
        if(flag)throw std::runtime_error("honest readonly table rejected");
        for(uint32_t rank=0;rank<count;++rank){
            auto previous=rank?expected[rank-1]:std::pair<uint32_t,uint32_t>{0,0};auto current=expected[rank];size_t at=(size_t)out[rank]*4;
            uint32_t wanted[4]={previous.first,previous.second,current.first,current.second};
            for(unsigned j=0;j<4;++j)if(args[at+j]!=wanted[j])throw std::runtime_error("readonly CPU/GPU mismatch");
        }
        for(auto x:tail)if(x!=0xa5a5a5a5u)throw std::runtime_error("readonly output overrun");
        std::printf("{\"entries\":%u,\"gpu_gather_sort_arguments_ns\":%.0f,\"cub_temporary_bytes\":%zu}\n",count,milliseconds*1000000.0,bytes);
        check(cudaEventDestroy(begin));check(cudaEventDestroy(end));
        // Invalid canonical field, out-of-range source row, and conflicting
        // duplicated key must be caught on the device, without a CPU scan.
        uint32_t bad=0x7fffffffu;check(cudaMemcpyAsync(source.p+4ull*size+physical(0,log),&bad,4,cudaMemcpyHostToDevice,stream));
        check(cudaMemsetAsync(status.p,0,4,stream));check(stwo_parent_readonly_gather_v1(rows.p,count,source.p,log,keys.p,values.p,status.p,stream));
        check(cudaMemcpyAsync(&flag,status.p,4,cudaMemcpyDeviceToHost,stream));check(cudaStreamSynchronize(stream));if(!flag)throw std::runtime_error("noncanonical readonly input accepted");++hostiles;
        bad=size;check(cudaMemcpyAsync(rows.p,&bad,4,cudaMemcpyHostToDevice,stream));check(cudaMemsetAsync(status.p,0,4,stream));
        check(stwo_parent_readonly_gather_v1(rows.p,count,source.p,log,keys.p,values.p,status.p,stream));
        check(cudaMemcpyAsync(&flag,status.p,4,cudaMemcpyDeviceToHost,stream));check(cudaStreamSynchronize(stream));if(!flag)throw std::runtime_error("readonly source overrun accepted");++hostiles;
        if(count>1){std::vector<uint32_t> equal(count,0),different(count);for(uint32_t i=0;i<count;++i)different[i]=i;
            check(cudaMemcpyAsync(sorted_keys.p,equal.data(),count*4,cudaMemcpyHostToDevice,stream));check(cudaMemcpyAsync(sorted_values.p,different.data(),count*4,cudaMemcpyHostToDevice,stream));
            check(cudaMemsetAsync(status.p,0,4,stream));check(stwo_parent_readonly_arguments_v1(output_rows.p,count,sorted_keys.p,sorted_values.p,result.p,count,status.p,stream));
            check(cudaMemcpyAsync(&flag,status.p,4,cudaMemcpyDeviceToHost,stream));check(cudaStreamSynchronize(stream));if(!flag)throw std::runtime_error("conflicting readonly duplicate accepted");++hostiles;}
        checked_words+=args.size();entries_total+=count;++cases;
    }
    check(cudaStreamDestroy(stream));
    std::printf("{\"status\":\"pass\",\"scope\":\"resident_readonly_sort_primitive\",\"fully_resident_prover\":false,\"cases\":%u,\"entries\":%llu,\"field_words\":%llu,\"hostiles\":%u}\n",cases,(unsigned long long)entries_total,(unsigned long long)checked_words,hostiles);
    return 0;
}catch(const std::exception&e){std::fprintf(stderr,"READONLY_GATE_FAILED %s\n",e.what());return 1;}
