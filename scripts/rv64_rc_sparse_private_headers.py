#!/usr/bin/env python3
"""Private indexed address view over byte-pinned existing production N2B math.
Only ColumnSlab.column addressing and the namespace/guard names are changed.
No butterfly, twiddle, zero extension or schedule expression is changed.
"""
from pathlib import Path
import hashlib,json,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
native=root/'src/backends/cuda/native/transform';manifest=[]
for name in ['transform_internal.cuh','n2b_fused.cuh']:
 text=(native/name).read_text();original=text
 text=text.replace('stwo::cuda::transform','stwo::cuda::rc_sparse_transform')
 text=text.replace('STWO_ZIG_CUDA_TRANSFORM_INTERNAL_CUH','STWO_ZIG_CUDA_RC_SPARSE_TRANSFORM_INTERNAL_CUH').replace('STWO_ZIG_CUDA_N2B_SMEM_CUH','STWO_ZIG_CUDA_RC_SPARSE_N2B_SMEM_CUH').replace('STWO_ZIG_CUDA_N2B_FUSED_CUH','STWO_ZIG_CUDA_RC_SPARSE_N2B_FUSED_CUH')
 if name=='transform_internal.cuh':
  old='''    size_t stride_words;

    __device__ __forceinline__ T *column(uint32_t index) const {
        return base + static_cast<size_t>(index) * stride_words;
    }'''
  new='''    size_t stride_words;
    const uint64_t *addresses = nullptr;
    const uint32_t *indices = nullptr;

    __device__ __forceinline__ T *column(uint32_t index) const {
        if (addresses) return reinterpret_cast<T *>(static_cast<uintptr_t>(addresses[index]));
        return base + static_cast<size_t>(indices ? indices[index] : index) * stride_words;
    }'''
  assert text.count(old)==1;text=text.replace(old,new)
 if name=='n2b_fused.cuh':
  old='{columns.base, columns.stride_words}'
  assert text.count(old)==2
  text=text.replace(old,'{columns.base, columns.stride_words, columns.addresses, columns.indices}')
 (out/name).write_text(text)
 manifest.append({'source':str(native/name),'source_sha256':hashlib.sha256(original.encode()).hexdigest(),'output':str(out/name),'output_sha256':hashlib.sha256(text.encode()).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'schema':'rv64-rc-sparse-private-n2b-addressing/v1','scope':'Address view only; identical original numerical functions','files':manifest},indent=2)+'\n')
