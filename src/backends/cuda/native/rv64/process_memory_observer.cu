// Observational only. Preload this SO so a25 + the frozen sparse addon register
// before CUDA EAGER initialization. No allocations, stage or transcript changes.
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <mutex>
extern "C" int stwo_exec_context_memory_info(void*,size_t*,size_t*);
static std::mutex output_mutex;
static int devices=0;
static int snapshot(const char*phase,int device){
  size_t free=0,total=0,stack=0;
  uint64_t used=0,reserved=0,used_high=0,reserved_high=0;
  cudaMemPool_t pool=nullptr;
  int current=-1;int status=int(cudaGetDevice(&current));
  if(!status&&current!=device)status=int(cudaSetDevice(device));
  if(!status)status=int(cudaMemGetInfo(&free,&total));
  if(!status)status=int(cudaDeviceGetLimit(&stack,cudaLimitStackSize));
  if(!status)status=int(cudaDeviceGetDefaultMemPool(&pool,device));
  if(!status)status=int(cudaMemPoolGetAttribute(pool,cudaMemPoolAttrUsedMemCurrent,&used));
  if(!status)status=int(cudaMemPoolGetAttribute(pool,cudaMemPoolAttrReservedMemCurrent,&reserved));
  if(!status)status=int(cudaMemPoolGetAttribute(pool,cudaMemPoolAttrUsedMemHigh,&used_high));
  if(!status)status=int(cudaMemPoolGetAttribute(pool,cudaMemPoolAttrReservedMemHigh,&reserved_high));
  size_t driver_free=0,driver_total=0;
  using Info=int(*)(size_t*,size_t*);
  static Info info=[](){void*driver=dlopen("libcuda.so.1",RTLD_NOW|RTLD_LOCAL);return driver?reinterpret_cast<Info>(dlsym(driver,"cuMemGetInfo_v2")):nullptr;}();
  const int driver_status=info?info(&driver_free,&driver_total):-1;
  {
    std::lock_guard<std::mutex>lock(output_mutex);
    std::fprintf(stderr,"GPU_PROCESS_MEMORY phase=%s device=%d status=%d free_bytes=%zu total_bytes=%zu stack_limit=%zu default_used_current=%llu default_reserved_current=%llu default_used_high=%llu default_reserved_high=%llu driver_status=%d driver_free_bytes=%zu driver_total_bytes=%zu\n",phase,device,status,free,total,stack,(unsigned long long)used,(unsigned long long)reserved,(unsigned long long)used_high,(unsigned long long)reserved_high,driver_status,driver_free,driver_total);
    std::fflush(stderr);
  }
  if(current>=0&&current!=device)(void)cudaSetDevice(current);
  return status ? status : (info && driver_status ? driver_status : 0);
}
static void finish(){
  for(int device=0;device<devices;++device){
    if(cudaSetDevice(device)==cudaSuccess)(void)cudaDeviceSynchronize();
    snapshot("terminal",device);
  }
}
__attribute__((constructor))static void start(){
  const char*enabled=std::getenv("STWO_RV64_PROCESS_MEMORY_OBSERVE");
  if(!enabled||enabled[0]!='1'||enabled[1])return;
  const int status=int(cudaGetDeviceCount(&devices));
  if(status){std::fprintf(stderr,"GPU_PROCESS_MEMORY_INIT status=%d\n",status);devices=0;return;}
  int previous=0;(void)cudaGetDevice(&previous);
  std::fprintf(stderr,"GPU_PROCESS_MEMORY_INIT preloaded=%d eager=%d devices=%d\n",std::getenv("LD_PRELOAD")!=nullptr,std::getenv("CUDA_MODULE_LOADING")&&std::getenv("CUDA_MODULE_LOADING")[0]=='E',devices);
  for(int device=0;device<devices;++device){
    if(cudaSetDevice(device)!=cudaSuccess||cudaFree(nullptr)!=cudaSuccess){std::fprintf(stderr,"GPU_PROCESS_MEMORY_INIT device=%d status=failed\n",device);continue;}
    snapshot("eager_baseline_before_arena_stack",device);
  }
  (void)cudaSetDevice(previous);
  std::atexit(finish);
}
extern "C" int stwo_rv64_process_memory_snapshot_on(void*ctx,const char*phase){
  size_t free=0,total=0;
  const int status=stwo_exec_context_memory_info(ctx,&free,&total);
  if(status||!phase)return status?status:int(cudaErrorInvalidValue);
  int device=0;const int selected=int(cudaGetDevice(&device));
  if(selected)return selected;
  return snapshot(phase,device);
}
