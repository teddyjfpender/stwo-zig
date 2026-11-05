// Opt-in diagnostic overlay. Forward every operation to the pinned native
// service; never allocate GPU memory or alter native admission/transcripts.
#include "pcs_native.h"
#include <array>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <execinfo.h>
#include <mutex>
#ifndef STWO_RV64_DIAGNOSTIC_BASE
#error "Set STWO_RV64_DIAGNOSTIC_BASE to the independently pinned base library"
#endif
namespace {
using Allocate=int(*)(void*,uint64_t,uint32_t,const uint32_t*,StwoRv64GpuLease*);
using Release=int(*)(void*,StwoRv64GpuLease*);
using Rebind=int(*)(void*,const StwoRv64GpuLease*,const uint32_t*,const uint32_t*);
using LastError=const char*(*)(void*);
using Live=int(*)(void*,uint64_t*,uint64_t*);
using Memory=int(*)(size_t*,size_t*);
struct Api{void*handle;Allocate allocate;Release release;Rebind rebind;LastError error;Live live;Memory memory;};
Api& api(){static Api value=[](){Api a{};a.handle=dlopen(STWO_RV64_DIAGNOSTIC_BASE,RTLD_NOW|RTLD_LOCAL);if(!a.handle){std::fprintf(stderr,"lease diagnostics base: %s\n",dlerror());std::abort();}
#define LOAD(F,N) a.F=reinterpret_cast<decltype(a.F)>(dlsym(a.handle,N));if(!a.F)std::abort()
LOAD(allocate,"stwo_rv64_gpu_lease_allocate");LOAD(release,"stwo_rv64_gpu_lease_release");LOAD(rebind,"stwo_rv64_gpu_lease_rebind");LOAD(error,"stwo_rv64_pcs_native_error");LOAD(live,"stwo_rv64_gpu_session_live_leases");
#undef LOAD
if(void*driver=dlopen("libcuda.so.1",RTLD_NOW|RTLD_LOCAL))a.memory=reinterpret_cast<Memory>(dlsym(driver,"cuMemGetInfo_v2"));return a;}();return value;}
struct Record{void*session=nullptr;StwoRv64GpuLease lease{};std::array<uint32_t,8> scope{};};
std::array<Record,16384> records{};std::mutex mutex;uint64_t dropped=0;
bool match(const Record&r,void*session,const StwoRv64GpuLease&l){return r.session==session&&r.lease.context_token==l.context_token&&r.lease.generation==l.generation&&r.lease.words==l.words;}
void quoted(const char*s){std::fputc('"',stderr);if(s)for(;*s;++s){const unsigned char c=*s;if(c=='"'||c=='\\')std::fprintf(stderr,"\\%c",c);else if(c<32)std::fprintf(stderr,"\\u%04x",unsigned(c));else std::fputc(c,stderr);}std::fputc('"',stderr);}
void scope(const uint32_t*s){std::fputc('"',stderr);for(unsigned i=0;i<8;++i)std::fprintf(stderr,"%08x",s?s[i]:0);std::fputc('"',stderr);}
void failure(void*session,int rc,uint64_t words,uint32_t kind,const uint32_t*requested){uint64_t counts[5]={},native_bytes=0;const int live_rc=api().live(session,counts,&native_bytes);size_t free=0,total=0;const int memory_rc=api().memory?api().memory(&free,&total):-1;
std::lock_guard<std::mutex>guard(mutex);uint64_t bytes[5]={},tracked[5]={};for(const auto&r:records)if(r.session==session&&r.lease.kind<5){bytes[r.lease.kind]+=4*r.lease.count;tracked[r.lease.kind]++;}
std::fprintf(stderr,"GPU_ALLOC_FAILURE {\"native_rc\":%d,\"requested_words\":%llu,\"requested_bytes\":%llu,\"kind\":%u,\"scope\":",rc,(unsigned long long)words,(unsigned long long)(words*4),kind);scope(requested);std::fprintf(stderr,",\"native_error\":");quoted(api().error(session));std::fprintf(stderr,",\"native_live_rc\":%d,\"native_live_bytes\":%llu,\"native_counts\":[",live_rc,(unsigned long long)native_bytes);for(int k=0;k<5;++k)std::fprintf(stderr,"%s%llu",k?",":"",(unsigned long long)counts[k]);std::fprintf(stderr,"],\"tracked_bytes_by_kind\":[");for(int k=0;k<5;++k)std::fprintf(stderr,"%s%llu",k?",":"",(unsigned long long)bytes[k]);std::fprintf(stderr,"],\"tracked_counts\":[");for(int k=0;k<5;++k)std::fprintf(stderr,"%s%llu",k?",":"",(unsigned long long)tracked[k]);std::fprintf(stderr,"],\"dropped_records\":%llu,\"driver_memory_rc\":%d,\"physical_free_bytes\":%llu,\"physical_total_bytes\":%llu}\n",(unsigned long long)dropped,memory_rc,(unsigned long long)free,(unsigned long long)total);
// Report the largest live scopes without allocating or perturbing the service.
std::array<std::array<uint32_t,8>,64> shown{};unsigned used=0;for(unsigned pass=0;pass<64;++pass){const Record*best=nullptr;uint64_t best_bytes=0;for(const auto&r:records){if(r.session!=session)continue;bool seen=false;for(unsigned i=0;i<used;++i)seen|=shown[i]==r.scope;if(seen)continue;uint64_t sum=0;for(const auto&s:records)if(s.session==session&&s.scope==r.scope)sum+=4*s.lease.count;if(sum>best_bytes){best=&r;best_bytes=sum;}}if(!best)break;shown[used++]=best->scope;uint64_t sb[5]={},sc[5]={};for(const auto&r:records)if(r.session==session&&r.scope==best->scope&&r.lease.kind<5){sb[r.lease.kind]+=4*r.lease.count;sc[r.lease.kind]++;}std::fprintf(stderr,"GPU_LIVE_SCOPE {\"scope\":");scope(best->scope.data());std::fprintf(stderr,",\"bytes\":%llu,\"bytes_by_kind\":[",(unsigned long long)best_bytes);for(int k=0;k<5;++k)std::fprintf(stderr,"%s%llu",k?",":"",(unsigned long long)sb[k]);std::fprintf(stderr,"],\"counts\":[");for(int k=0;k<5;++k)std::fprintf(stderr,"%s%llu",k?",":"",(unsigned long long)sc[k]);std::fprintf(stderr,"]}\n");}std::fflush(stderr);void*frames[32];const int n=backtrace(frames,32);std::fprintf(stderr,"GPU_ALLOC_BACKTRACE frames=%d\n",n);backtrace_symbols_fd(frames,n,2);}
}
extern "C" int stwo_rv64_gpu_lease_allocate(void*s,uint64_t words,uint32_t kind,const uint32_t key[8],StwoRv64GpuLease*out){const int rc=api().allocate(s,words,kind,key,out);if(rc){failure(s,rc,words,kind,key);return rc;}std::lock_guard<std::mutex>guard(mutex);for(auto&r:records)if(!r.session){r.session=s;r.lease=*out;if(key)std::copy_n(key,8,r.scope.begin());return rc;}++dropped;return rc;}
extern "C" int stwo_rv64_gpu_lease_release(void*s,StwoRv64GpuLease*l){const auto before=l?*l:StwoRv64GpuLease{};const int rc=api().release(s,l);if(!rc){std::lock_guard<std::mutex>guard(mutex);for(auto&r:records)if(match(r,s,before)){r={};break;}}return rc;}
extern "C" int stwo_rv64_gpu_lease_rebind(void*s,const StwoRv64GpuLease*l,const uint32_t from[8],const uint32_t to[8]){const int rc=api().rebind(s,l,from,to);if(!rc&&l&&to){std::lock_guard<std::mutex>guard(mutex);for(auto&r:records)if(match(r,s,*l)){std::copy_n(to,8,r.scope.begin());break;}}return rc;}
