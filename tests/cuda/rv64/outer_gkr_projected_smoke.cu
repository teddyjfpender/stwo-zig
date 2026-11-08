#include "context_owner.cuh"
#include "rv64/outer_gkr_projector.cuh"
#include <algorithm>
using namespace stwo::cuda::rv64;
#include "rv64/binding.h"
#include "rv64/composition_finalize.h"
struct StwoCircuitOuterBinding { StwoCircuitOuterGkrSource source; const uint32_t *metadata; StwoRv64Plane eq,prefix; };
extern "C" int stwo_circuit_outer_gkr_binding_on(void*,uint32_t,const StwoCircuitOuterBinding*);
static uint32_t physical(uint32_t k,uint32_t log){uint32_t c=(k&1)?(1u<<log)-(k+1)/2:k/2,p=0;for(uint32_t i=0;i<log;++i){p=(p<<1)|(c&1);c>>=1;}return p;}
static OM31 eq_at(const std::vector<uint32_t>& point,uint32_t row,uint32_t log){OM31 q=one();for(uint32_t i=0;i<log;++i){const auto z=from_words(point.data()+8*i);q=mul(q,(row>>(log-1-i))&1?z:sub(one(),z));}return q;}
using namespace stwo::cuda::rv64;
extern "C" int stwo_circuit_outer_gkr_validate_on(void*, uint32_t, const void*, uint32_t);
extern "C" int stwo_circuit_outer_gkr_layer_on(void*, uint32_t, const void*, uint32_t, uint32_t, StwoRv64Plane, StwoRv64Plane);
extern "C" int stwo_circuit_outer_gkr_sum_on(void*, uint32_t, const void*, uint32_t, StwoRv64Plane, const uint32_t*, StwoRv64Plane, StwoRv64Plane, StwoRv64Plane);
extern "C" int stwo_circuit_outer_gkr_fold_on(void*, uint32_t, const void*, uint32_t, const uint32_t*, StwoRv64Plane, StwoRv64Plane);

static Fraction host_fraction(const StwoCircuitOuterGkrSource &s, uint32_t index) {
  switch (s.component) {
    case 2: return outer_gkr::Source<2>{s}.get(index);
    case 3: return outer_gkr::Source<3>{s}.get(index);
    case 4: return outer_gkr::Source<4>{s}.get(index);
    case 6: return outer_gkr::Source<6>{s}.get(index);
    default: throw std::runtime_error("unsupported source");
  }
}
static void same(Owner &owner, StwoRv64Plane a, StwoRv64Plane b) {
  if (owner.read(a) != owner.read(b)) throw std::runtime_error("projected/materialized mismatch");
}
int main() {
  try {
    uint32_t cases = 0, fractions = 0, mutants = 0, poles = 0,bindings=0,eq23=0,aux23=0;
    for (uint32_t row_log : {4u, 12u}) for (uint32_t kind : {2u, 3u, 4u, 6u}) {
      const uint32_t lookups = kind == 2 ? 12 : kind == 3 ? 5 : kind == 4 ? 26 : 16;
      for (uint32_t first = 0; first < lookups;) {
        const uint32_t lanes = 1u << (31 - __builtin_clz(lookups - first));
        const uint32_t lane_log = 31 - __builtin_clz(lanes), rows = 1u << row_log, count = lanes * rows;
        Owner owner(0);
        std::vector<uint32_t> fixed(rows * outer_gkr::tuples::kPpWidths[kind]);
        std::vector<uint32_t> main(rows * outer_gkr::tuples::kBaseWidths[kind]);
        std::vector<uint32_t> params(56);
        for (uint32_t i = 0; i < fixed.size(); ++i) fixed[i] = 1 + 13 * i;
        for (uint32_t i = 0; i < main.size(); ++i) main[i] = 1 + 17 * i;
        for (uint32_t i = 0; i < params.size(); ++i) params[i] = 1 + 19 * i;
        uint32_t status = 0;
        const StwoCircuitOuterGkrSource host{fixed.empty() ? nullptr : fixed.data(), main.data(), params.data(), &status,
                                            fixed.size(), main.size(), kind, row_log, first, lane_log};
        std::vector<uint32_t> numerators(8 * count), denominators(8 * count);
        for (uint32_t i = 0; i < count; ++i) {
          const auto f = host_fraction(host, i);
          store(numerators.data(), count, i, f.n);
          store(denominators.data(), count, i, f.d);
        }
        if (status) throw std::runtime_error("host source pole");
        const auto fp = owner.plane(std::max(size_t(1), fixed.size()), 1);
        const auto mp = owner.plane(main.size(), 1), pp = owner.plane(56, 1), verdict = owner.plane(1, 1);
        if (!fixed.empty()) owner.upload(fp, fixed);
        owner.upload(mp, main); owner.upload(pp, params); owner.upload(verdict, {0});
        const auto n = owner.plane(count, 8), d = owner.plane(count, 8);
        owner.upload(n, numerators); owner.upload(d, denominators);
        const StwoCircuitOuterGkrSource source{fixed.empty() ? nullptr : fp.words, mp.words, pp.words, verdict.words,
                                              fixed.size(), main.size(), kind, row_log, first, lane_log};
        const auto on = owner.plane(count / 2, 8), od = owner.plane(count / 2, 8);
        const auto rn = owner.plane(count / 2, 8), rd = owner.plane(count / 2, 8);
        const auto qn = owner.plane(count / 4, 8), qd = owner.plane(count / 4, 8);
        const auto sn = owner.plane(count / 4, 8), sd = owner.plane(count / 4, 8);
        const auto assignment = owner.plane(8, 1);
        owner.upload(assignment, {5,7,11,13,17,19,23,29});
        const auto eq = owner.plane(count / 4, 8);
        std::vector<uint32_t> eq_values(8 * (count / 4));
        for (uint32_t i = 0; i < eq_values.size(); ++i) eq_values[i] = 3 + 23 * i;
        owner.upload(eq, eq_values);
        const uint32_t groups = std::max(1u, (count / 4 + 127) / 128);
        const auto a = owner.plane(2 * groups, 8), b = owner.plane(2 * groups, 8);
        const auto actual = owner.plane(2, 8), reference = owner.plane(2, 8);
        CHECK(stwo_exec_context_sync(owner.ctx));
        CHECK(stwo_circuit_outer_gkr_validate_on(owner.ctx, 0, &source, count));
        CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx, 0, &source, count, 1, on, od));
        CHECK(stwo_rv64_gkr_layer_on(owner.ctx, 0, n, d, count, 1, rn, rd));
        same(owner, on, rn); same(owner, od, rd);
        CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx, 0, &source, count, 2, qn, qd));
        CHECK(stwo_rv64_gkr_layer_on(owner.ctx, 0, n, d, count, 2, sn, sd));
        same(owner, qn, sn); same(owner, qd, sd);
        CHECK(stwo_circuit_outer_gkr_sum_on(owner.ctx, 0, &source, count, eq, assignment.words, a, b, actual));
        CHECK(stwo_rv64_gkr_sum_on(owner.ctx, 0, n, d, count, eq, assignment.words, a, b, reference));
        same(owner, actual, reference);
        CHECK(stwo_circuit_outer_gkr_fold_on(owner.ctx, 0, &source, count, assignment.words, on, od));
        CHECK(stwo_rv64_gkr_fold_on(owner.ctx, 0, n, d, count, assignment.words, rn, rd));
        same(owner, on, rn); same(owner, od, rd);
        if (owner.read(verdict)[0]) throw std::runtime_error("device source status");
        // Range/geometry/alias mutants must refuse BEFORE a kernel launch.
        auto bad = source; bad.main_words--;
        if (!stwo_circuit_outer_gkr_validate_on(owner.ctx,0,&bad,count)) throw std::runtime_error("short source admitted");
        ++mutants;
        bad = source; bad.lane_first = lookups;
        if (!stwo_circuit_outer_gkr_validate_on(owner.ctx,0,&bad,count)) throw std::runtime_error("wrong lane group admitted");
        ++mutants;
        // n/d are materialized controls, so point one output into the actual source.
        auto alias = on; alias.words = const_cast<uint32_t*>(source.main);
        if (!stwo_circuit_outer_gkr_layer_on(owner.ctx,0,&source,count,1,alias,od)) throw std::runtime_error("MAIN-output alias admitted");
        ++mutants;
        if(first==0){
          auto binding_eq=owner.plane(rows,8), prefix=owner.plane(rows,8), claim=owner.plane(8,1);
          auto point_plane=owner.plane(8*row_log,1),metadata_plane=owner.plane(28*8,1);
          std::vector<uint32_t> point(8*row_log),metadata(28*8),eq_values(8*rows),delta(8*rows),prefix_values(8*rows);
          for(uint32_t i=0;i<point.size();++i)point[i]=3+31*i;
          for(uint32_t i=0;i<27*8;++i)metadata[i]=7+37*i;
          const auto gamma=from_words(metadata.data()+26*8);OM31 target=zero();
          std::vector<OM31> projected(rows);
          for(uint32_t row=0;row<rows;++row){
            OM31 projection=zero();for(uint32_t term=0;term<lookups;++term){auto h=host;h.lane_first=term;h.lane_log=0;auto f=host_fraction(h,row);projection=add(projection,mul(from_words(metadata.data()+8*term),add(f.n,mul(gamma,f.d))));}
            auto e=eq_at(point,row,row_log);store(eq_values.data(),rows,row,e);projected[row]=mul(e,projection);target=add(target,projected[row]);
          }
          const auto uniform=scale(target,q::inverse(rows));store(metadata.data()+27*8,1,0,uniform);
          OM31 sum=zero();for(uint32_t k=0;k<rows;++k){auto row=physical(k,row_log);auto value=sub(projected[row],uniform);store(delta.data(),rows,row,value);sum=add(sum,value);store(prefix_values.data(),rows,row,sum);}if(!is_zero(sum))throw std::runtime_error("CPU cyclic debt");
          owner.upload(point_plane,point);owner.upload(metadata_plane,metadata);CHECK(stwo_exec_context_sync(owner.ctx));
          CHECK(stwo_rv64_binding_eq_on(owner.ctx,0,point_plane.words,row_log,binding_eq,verdict.words));if(owner.read(binding_eq)!=eq_values)throw std::runtime_error("full Eq mismatch");
          StwoCircuitOuterBinding binding{source,metadata_plane.words,binding_eq,prefix};CHECK(stwo_circuit_outer_gkr_binding_on(owner.ctx,0,&binding));if(owner.read(prefix)!=delta)throw std::runtime_error("raw binding delta mismatch");
          uint64_t scratch_words=0;for(uint32_t n=rows;n>1;){n=(n+127)/128;scratch_words+=uint64_t(n)*8;}
          auto scratch=owner.plane(scratch_words,1);StwoRv64PrefixScan scan{prefix,scratch.words,scratch_words,claim.words,verdict.words,row_log,0,{0,0}};CHECK(stwo_rv64_prefix_scan_on(owner.ctx,0,&scan));
          if(owner.read(prefix)!=prefix_values||owner.read(verdict)[0])throw std::runtime_error("cyclic prefix mismatch");++bindings;
        }
        if (kind == 6) {
          // Real zero-weight0/0 table fractions must stay poles, rather than
          // becoming neutral padding (0,1). The sticky verdict also rejects.
          owner.upload(mp, std::vector<uint32_t>(main.size(), 0));
          owner.upload(pp, std::vector<uint32_t>(56, 0));
          owner.upload(verdict, {0});
          CHECK(stwo_exec_context_sync(owner.ctx));
          CHECK(stwo_circuit_outer_gkr_layer_on(owner.ctx,0,&source,count,1,on,od));
          if (!owner.read(verdict)[0]) throw std::runtime_error("real pole not reported");
          const auto values = owner.read(od);
          if (std::any_of(values.begin(), values.end(), [](uint32_t x) { return x != 0; }))
            throw std::runtime_error("real pole laundered into padding");
          ++poles;
        }
        owner.close();
        ++cases; fractions += count; first += lanes;
      }
    }
    {Owner owner(0);const uint32_t log=23,rows=1u<<log;auto eq=owner.plane(rows,8),p=owner.plane(8*log,1),status=owner.plane(1,1);std::vector<uint32_t> point(8*log);for(uint32_t i=0;i<point.size();++i)point[i]=11+43*i;owner.upload(p,point);owner.upload(status,{0});CHECK(stwo_exec_context_sync(owner.ctx));CHECK(stwo_rv64_binding_eq_on(owner.ctx,0,p.words,log,eq,status.words));auto actual=owner.read(eq);for(uint32_t row: {0u,1u,2u,3u,127u,128u,1023u,1024u,1048575u,4194304u,rows-2,rows-1}){if(!is_zero(sub(load(actual.data(),rows,row),eq_at(point,row,log))))throw std::runtime_error("Eq23 sample mismatch");++eq23;}if(owner.read(status)[0])throw std::runtime_error("Eq23 status");
      auto auxiliary=owner.plane(uint64_t(10)*rows,1),hc=owner.plane(16*log,1);std::vector<uint32_t> carry(16*log);for(uint32_t i=0;i<carry.size();++i)carry[i]=17+41*i;owner.upload(hc,carry);CHECK(stwo_exec_context_sync(owner.ctx));uint32_t launches=0;CHECK(stwo_rv64_composition_auxiliary_on(owner.ctx,0,hc.words,auxiliary.words,log,&launches));if(launches!=1)throw std::runtime_error("auxiliary launch count");auto av=owner.read(auxiliary);
      for(uint32_t row:{0u,1u,2u,3u,127u,128u,1023u,1024u,1048575u,4194304u,rows-2,rows-1}){const auto half=row&1u,bits=half?row:(rows-1)^row,ci=uint32_t(__builtin_clz(bits))-(32-log);if(av[row]!=(row==0)||av[uint64_t(rows)+row]!=(row+1==rows))throw std::runtime_error("auxiliary anchor mismatch");for(uint32_t c=0;c<8;++c)if(av[uint64_t(c+2)*rows+row]!=carry[(half*log+ci)*8+c])throw std::runtime_error("auxiliary carry mismatch");++aux23;}owner.close();}
    std::printf("{\"passed\":true,\"source_groups\":%u,\"source_fractions\":%u,\"geometry_alias_mutants\":%u,\"real_zero_weight_poles\":%u,\"layer_sum_fold_parity\":true,\"cyclic_binding_cases\":%u,\"eq23_samples\":%u,\"aux23_samples\":%u}\n", cases, fractions, mutants, poles, bindings, eq23, aux23);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr,"ERROR %s\n",e.what()); return 1;
  }
}
