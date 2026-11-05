// Actual CPU source program: fixture contains independent Zig IR evaluations.
// Include the receiver-generated source selected by the build include path.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "native-cpu-keccak.cu"
using namespace stwo::cuda::rv64;
__global__ void raw_values(native_cpu_keccak_Source s,uint32_t count,StwoRv64Plane n,StwoRv64Plane d){
  const uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
  const auto f=s.get(i);store(n.words,n.stride,i,f.n);store(d.words,d.stride,i,f.d);
}
static std::vector<uint32_t> planes(const std::vector<OM31>&v){
  std::vector<uint32_t> out(v.size()*8);for(size_t i=0;i<v.size();++i)store(out.data(),v.size(),i,v[i]);return out;
}
int main(int argc,char**argv){try{
  if(argc!=2)throw std::runtime_error("fixture path required");FixtureWords f(argv[1]);const auto h=f.take(10);
  if(h[0]!=0x4e475232||h[1]!=1||h[2]!=5)throw std::runtime_error("native source fixture header");
  const uint32_t rows=1u<<h[2];uint32_t counts[4]{},total=0;
  for(uint32_t k=0;k<4;++k){if(h[6+k]){uint32_t lanes=1;while(lanes<h[6+k])lanes*=2;counts[k]=rows*lanes;total+=counts[k];}}
  const auto fixed=f.take(rows*h[3]),main=f.take(rows*h[4]),parameters=f.take(8*h[5]),ns=f.take(total),ds=f.take(8*total);
  if(f.position!=f.data.size())throw std::runtime_error("native source fixture trailing bytes");
  Owner o(0);auto upload=[&](const std::vector<uint32_t>&v){auto p=o.plane(v.size(),1);o.upload(p,v);return p;};
  auto df=upload(fixed),dm=upload(main),dp=upload(parameters),status=upload({0});
  native_cpu_keccak_Source source;source.fixed=df.words;source.main=dm.words;source.parameters=dp.words;source.status=status.words;
  source.fixed_words=fixed.size();source.main_words=main.size();source.row_log=h[2];source.reserved0=source.reserved1=0;
  CHECK(stwo_exec_context_sync(o.ctx));void*stream=nullptr;CHECK(stwo_exec_context_lane_stream(o.ctx,1,&stream));
  std::vector<OM31> projection(rows,zero());std::vector<uint32_t> weights(4*256*8,0);
  for(uint32_t i=0;i<4*256;++i)for(uint32_t c=0;c<8;++c)weights[8*i+c]=i+c+3;
  const std::vector<uint32_t> meta{2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53};
  const auto gamma=from_words(meta.data()),target=from_words(meta.data()+8);
  uint32_t at=0;
  for(uint32_t kind=0;kind<4;++kind){if(!counts[kind])continue;source.kind=kind;const auto count=counts[kind];
    std::vector<OM31> n(count),d(count);for(uint32_t i=0;i<count;++i){n[i]=base(ns[at+i]);d[i]=from_words(ds.data()+8*(at+i));}
    CHECK(native_cpu_keccak_validate(o.ctx,1,&source,count));
    auto on=o.plane(count,8),od=o.plane(count,8);
    raw_values<<<(count+127)/128,128,0,reinterpret_cast<cudaStream_t>(stream)>>>(source,count,on,od);CHECK(cudaPeekAtLastError());
    fixture_equal("native source original numerator",o.read(on),planes(n));fixture_equal("native source original denominator",o.read(od),planes(d));
    auto ln=o.plane(count/2,8),ld=o.plane(count/2,8);CHECK(native_cpu_keccak_layer(o.ctx,1,&source,count,1,ln,ld));
    std::vector<OM31> en(count/2),ed(count/2);for(uint32_t i=0;i<count/2;++i){auto v=combine({n[2*i],d[2*i]},{n[2*i+1],d[2*i+1]});en[i]=v.n;ed[i]=v.d;}
    fixture_equal("native source product numerator",o.read(ln),planes(en));fixture_equal("native source product denominator",o.read(ld),planes(ed));
    const auto dx=upload(std::vector<uint32_t>(meta.begin(),meta.begin()+8));CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(native_cpu_keccak_fold(o.ctx,1,&source,count,dx.words,ln,ld));
    for(uint32_t i=0;i<count/2;++i){en[i]=fold(n[i],n[i+count/2],gamma);ed[i]=fold(d[i],d[i+count/2],gamma);}
    fixture_equal("native source first fold numerator",o.read(ln),planes(en));fixture_equal("native source first fold denominator",o.read(ld),planes(ed));
    const uint32_t terms=count/4,groups=(terms+127)/128;auto eq=o.plane(terms,8),a=o.plane(2*groups,8),b=o.plane(2*groups,8),sum=o.plane(2,8);
    std::vector<OM31> ev(terms);Pair expected{zero(),zero()};for(uint32_t i=0;i<terms;++i){ev[i]=base(i+3);const auto j=2*i,k=2*(terms+i);auto v=sum_term({n[j],d[j]},{n[j+1],d[j+1]},{n[k],d[k]},{n[k+1],d[k+1]},ev[i],gamma);expected.at0=add(expected.at0,v.at0);expected.at2=add(expected.at2,v.at2);}
    o.upload(eq,planes(ev));CHECK(stwo_exec_context_sync(o.ctx));CHECK(native_cpu_keccak_sum(o.ctx,1,&source,count,eq,dx.words,a,b,sum));fixture_equal("native source sumcheck",o.read(sum),planes({expected.at0,expected.at2}));
    for(uint32_t lane=0;lane<count/rows;++lane)for(uint32_t row=0;row<rows;++row){const auto weight=from_words(weights.data()+8*(kind*256+lane));const auto i=lane*rows+row;projection[row]=add(projection[row],mul(weight,add(n[i],mul(gamma,d[i]))));}
    if(!native_cpu_keccak_validate(o.ctx,1,&source,count*2))throw std::runtime_error("wrong source count accepted");
    at+=count;std::printf("NATIVE_SOURCE kind=%u facts=%u exact_originals=true layer_fold_sum=true\n",kind,count);
  }
  auto dw=upload(weights),metadata=upload(meta),eq=o.plane(rows,8),prefix=o.plane(rows,8);
  std::vector<OM31> e(rows),expected(rows);for(uint32_t row=0;row<rows;++row){e[row]=base(row+2);expected[row]=sub(mul(e[row],projection[row]),target);}
  o.upload(eq,planes(e));CHECK(stwo_exec_context_sync(o.ctx));source.kind=0;
  CHECK(native_cpu_keccak_binding(o.ctx,1,&source,dw.words,metadata.words,eq,prefix));fixture_equal("native source weighted all-kind binding",o.read(prefix),planes(expected));
  if(!native_cpu_keccak_binding(o.ctx,1,&source,dw.words,metadata.words,eq,eq))throw std::runtime_error("binding alias accepted");
  if(o.read(status)[0])throw std::runtime_error("unexpected native source verdict");
  auto wrong=source;wrong.reserved0=1;if(!native_cpu_keccak_validate(o.ctx,1,&wrong,counts[0]))throw std::runtime_error("reserved descriptor accepted");
  Owner foreign(0);wrong=source;wrong.parameters=foreign.plane(parameters.size(),1).words;if(!native_cpu_keccak_validate(o.ctx,1,&wrong,counts[0]))throw std::runtime_error("foreign source accepted");foreign.close();
  std::puts("NATIVE_SOURCE binding=true poison_cases=4 input_fraction_device_bytes=0");o.close();return 0;
}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
