// Exercises the batched inverse and ragged graph on nonuniform denominators.
// Reuse the resident allocation harness and ABI declarations from the small
// independent add-ap fixture; expected values below use scalar modular math.
#define main stwo_add_ap_fixture_main
#include "native_cairo_relation_smoke.cpp"
#undef main
#include <array>
namespace {
using Q = std::array<std::uint32_t, 4>;
constexpr std::uint64_t prime = 2147483647;
Q plus(Q a,Q b){for(int i=0;i<4;i++)a[i]=(std::uint64_t(a[i])+b[i])%prime;return a;}
Q minus(Q a,Q b){for(int i=0;i<4;i++)a[i]=(std::uint64_t(a[i])+prime-b[i])%prime;return a;}
Q times(Q a,Q b){
 auto cm=[](std::uint32_t a,std::uint32_t b,std::uint32_t c,std::uint32_t d){return std::array<std::uint32_t,2>{std::uint32_t((std::uint64_t(a)*c+prime-(std::uint64_t(b)*d)%prime)%prime),std::uint32_t((std::uint64_t(a)*d+std::uint64_t(b)*c)%prime)};};
 auto ac=cm(a[0],a[1],b[0],b[1]),bd=cm(a[2],a[3],b[2],b[3]);auto rot=cm(2,1,bd[0],bd[1]);
 auto ad=cm(a[0],a[1],b[2],b[3]),bc=cm(a[2],a[3],b[0],b[1]);
 return {std::uint32_t((std::uint64_t(ac[0])+rot[0])%prime),std::uint32_t((std::uint64_t(ac[1])+rot[1])%prime),std::uint32_t((std::uint64_t(ad[0])+bc[0])%prime),std::uint32_t((std::uint64_t(ad[1])+bc[1])%prime)};
}
Q inv(Q a){unsigned __int128 e=prime;e=e*prime*prime*prime-2;Q r{1,0,0,0};while(e){if(e&1)r=times(r,a);a=times(a,a);e>>=1;}return r;}
bool run_nonuniform(){
 Arena arena;if(!arena.create())return false;
 const Q z{127288171,1125323933,915465708,1234568098},alpha{1153592825,1170056014,2144565551,617132091};
 std::uint32_t challenges[8];std::copy(z.begin(),z.end(),challenges);std::copy(alpha.begin(),alpha.end(),challenges+4);
 auto*drawn=arena.upload(challenges,8);auto*powers=arena.allocate(8);auto*zz=arena.allocate(4);
 std::vector<std::uint32_t*>sources,descriptors,outputs,denominators,sums;
 std::vector<std::uint32_t>geometry;std::vector<Q>expected;
 std::uint32_t pair_blocks=0,inverse_blocks=0,row_blocks=0;
 for(std::uint32_t rows:{16u,4096u,2048u}){
  std::vector<std::uint32_t> words(rows*3);Q sum{};
  for(std::uint32_t r=0;r<rows;r++){words[r]=428564188;words[rows+r]=r*7919u+17;words[2*rows+r]=(r%7==0)?0:1;Q den=minus(plus(Q{428564188,0,0,0},times(Q{words[rows+r],0,0,0},alpha)),z);sum=plus(sum,times(Q{words[2*rows+r],0,0,0},inv(den)));}
  auto*source=arena.upload(words.data(),words.size());sources.push_back(arena.pointerTable({source}));
  const std::uint32_t descriptor[16]={1,0,0,2,428564188,2,2,0,0,0,0,0,0,0,0,0};descriptors.push_back(arena.upload(descriptor,16));
  auto*out=arena.allocate(rows*4);outputs.push_back(arena.pointerTable({out,out+rows,out+rows*2,out+rows*3}));
  auto*den=arena.allocate(rows*4);denominators.push_back(den);sums.push_back(arena.allocate(4));
  auto rb=(rows+255)/256,ib=(rows+1023)/1024;
  std::uint32_t g[11]={pair_blocks,rb,inverse_blocks,ib,row_blocks,rb,rows,1,rows,0,0};geometry.insert(geometry.end(),g,g+11);pair_blocks+=rb;inverse_blocks+=ib;row_blocks+=rb;expected.push_back(sum);
 }
 auto*st=arena.pointerTable(sources),*dt=arena.pointerTable(descriptors),*ot=arena.pointerTable(outputs),*nt=arena.pointerTable(denominators),*ct=arena.pointerTable(sums);auto*geo=arena.upload(geometry.data(),geometry.size());auto*partial=arena.allocate(row_blocks*4);auto*scan=arena.allocate(row_blocks*4);
 if(!arena.sync("upload")||!check(stwo_relation_expand_challenges_on(drawn,powers,2,zz,arena.stream()),"challenges")||!check(stwo_relation_pairs_global_on(st,dt,ot,nt,geo,3,pair_blocks,powers,2,zz,arena.stream()),"pairs")||!check(stwo_relation_fraction_chain_global_on(ot,nt,geo,3,inverse_blocks,row_blocks,arena.stream()),"fractions")||!check(stwo_relation_tail_global_on(ot,ct,geo,3,row_blocks,partial,row_blocks,scan,row_blocks*4,arena.stream()),"tail"))return false;
 std::vector<Q>actual(3);for(int i=0;i<3;i++)if(!arena.download(actual[i].data(),sums[i],4))return false;if(!arena.sync("claims"))return false;
 bool pass=actual==expected;for(int i=0;i<3;i++)if(actual[i]!=expected[i]){std::fprintf(stderr,"nonuniform ragged claim mismatch instance=%d expected=%u,%u,%u,%u actual=%u,%u,%u,%u\n",i,expected[i][0],expected[i][1],expected[i][2],expected[i][3],actual[i][0],actual[i][1],actual[i][2],actual[i][3]);}
 return arena.destroy()&&pass;
}
}
int main(){if(!run_nonuniform())return 1;std::puts("Cairo relation nonuniform ragged inverse passed: 16, 4096, 2048 rows; transcript-sized challenges; zero multiplicities");return 0;}
