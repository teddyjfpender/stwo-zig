#!/usr/bin/env python3
"""CPU numerical check of the actual curve CUDA kernel body against native fixtures.

This deliberately does not emulate CUDA scheduling/custody or claim GPU
qualification. It catches arithmetic and whole-column layout errors before
renting a GPU; cpu_witness_smoke.cu remains the device qualification gate.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("fixtures", type=Path)
parser.add_argument("--compiler", default="c++")
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
s=(root/'src/backends/cuda/native/rv64/curve_witness.cu').read_text();s=s[:s.index('template <class L> int launch')];s=s.replace('#include "custody.cuh"','');
head='''#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <fstream>
#define __global__
struct Dim {uint32_t x;}; static Dim blockIdx{},blockDim{},threadIdx{};
static uint32_t __brev(uint32_t v){uint32_t r=0;for(int i=0;i<32;++i){r=(r<<1)|(v&1);v>>=1;}return r;}
static void atomicOr(uint32_t*p,uint32_t v){*p|=v;}
static void atomicAdd(uint32_t*p,uint32_t v){*p+=v;}
'''
tail='''} }
using namespace stwo::cuda::rv64;
template<class L> void run(StwoRv64CurveWitness j){blockDim.x=1;threadIdx.x=0;for(blockIdx.x=0;blockIdx.x<(1u<<j.log);++blockIdx.x)curve::witness<L>(j);for(threadIdx.x=0;threadIdx.x<256;++threadIdx.x)curve::counts<L>(j);}
int main(int argc,char**argv){try{if(argc!=2)return 2;for(unsigned id=0;id<15;++id){std::string path=std::string(argv[1])+"/case-"+std::to_string(id)+".bin";std::ifstream f(path,std::ios::binary|std::ios::ate);size_t bytes=f.tellg();f.seekg(0);std::vector<uint32_t>b(bytes/4);f.read((char*)b.data(),bytes);auto*h=b.data();uint32_t words[5]={32,16,32,48,40};size_t inputs=h[4]*words[h[7]],n=1u<<h[3];std::vector<uint32_t>main(h[6]*n),hist(256);uint32_t status=0;StwoRv64CurveWitness j{h+8,main.data(),hist.data(),&status,inputs,main.size(),h[4],h[5],h[3],h[7]};switch(h[7]){case 0:run<curve::bn254_g1_add>(j);break;case 1:run<curve::bn254_g1_double>(j);break;case 2:run<curve::bn254_fp2_mul>(j);break;case 3:run<curve::bls12_381_fp2_mul>(j);break;case 4:run<curve::arith384_mont>(j);break;}if(status)throw std::runtime_error("status="+std::to_string(status)+" case="+std::to_string(id));for(size_t i=0;i<main.size();++i)if(main[i]!=b[8+inputs+i])throw std::runtime_error("MAIN case="+std::to_string(id)+" col="+std::to_string(i/n)+" row="+std::to_string(i%n)+" actual="+std::to_string(main[i])+" expected="+std::to_string(b[8+inputs+i]));for(size_t i=0;i<256;++i)if(hist[i]!=b[8+inputs+main.size()+i])throw std::runtime_error("hist mismatch");printf("PASS host numeric kernel body case=%u kind=%u calls=%u main=%zu\\n",id,h[7],h[4],main.size());}return 0;}catch(const std::exception&e){fprintf(stderr,"FAIL %s\\n",e.what());return 1;}}
'''
with tempfile.TemporaryDirectory(prefix="rv64-curve-host-") as tmp:
    source = Path(tmp) / "curve.cpp"
    executable = Path(tmp) / "curve"
    source.write_text(head+s+tail)
    subprocess.run([args.compiler, "-O2", "-std=c++17",
        "-I"+str(root/"tests/cuda/rv64/host_include"),
        "-I"+str(root/"src/backends/cuda/native"),
        "-I"+str(root/"src/backends/cuda/native/rv64"),
        str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable), str(args.fixtures.resolve())], check=True)

