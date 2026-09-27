#[path="/tmp/stwo-recursion-peer-research-20260921/zisk/precompiles/helpers/src/blake3/blake3f/mod.rs"] mod blake3f;
#[path="/tmp/stwo-recursion-peer-research-20260921/zisk/precompiles/helpers/src/keccak/keccak_f/mod.rs"] mod witness_keccak;
use sha2::{Digest,Sha256};
#[no_mangle]
pub unsafe extern "C" fn peer_keccak(state:*mut u64) {tiny_keccak::keccakf(&mut *(state as *mut [u64;25]));}
#[no_mangle]
pub unsafe extern "C" fn peer_blake3(cv:*const u32,block:*const u32,counter:u64,len:u32,flags:u32,out:*mut u32) {
 let cv=&*(cv as *const [u32;8]);let block=&*(block as *const [u32;16]);let out=&mut *(out as *mut [u32;16]);
 out[..8].copy_from_slice(cv);out[8..12].copy_from_slice(&[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a]);out[12]=counter as u32;out[13]=(counter>>32) as u32;out[14]=len;out[15]=flags;
 blake3f::blake3_f(out,block);for i in 0..8 {out[i]^=out[i+8];out[i+8]^=cv[i];}
}
#[no_mangle]
pub unsafe extern "C" fn peer_sha(input:*const u8,n:u32,out:*mut u8){let digest=Sha256::digest(std::slice::from_raw_parts(input,n as usize));std::ptr::copy_nonoverlapping(digest.as_ptr(),out,32);}
#[no_mangle]
pub unsafe extern "C" fn peer_keccak_witness(state:*mut u64){let a=&mut *(state as *mut [u64;25]);let mut s=witness_keccak::keccakf_state_from_linear(a);witness_keccak::keccak_f(&mut s);for x in 0..5{for y in 0..5{a[x+y*5]=0;for z in 0..64{a[x+y*5]|=(s[x][y][z] as u64)<<z;}}}}
#[no_mangle]
pub extern "C" fn peer_primitive_batch(op:u32,n:u32,rounds:u32)->u64{
 let mut sum=0u64;let mut data=vec![0u8;(n as usize).max(8)];for(i,v)in data.iter_mut().enumerate(){*v=i as u8;}
 for r in 0..rounds{
  if op==0||op==3 {let mut s=[0u64;25];for(i,v)in s.iter_mut().enumerate(){*v=i as u64;}s[0]=r as u64;if op==0{tiny_keccak::keccakf(&mut s);}else{unsafe{peer_keccak_witness(s.as_mut_ptr());}}for v in s {sum=sum.wrapping_add(v);}}
  else if op==1 {data[..4].copy_from_slice(&r.to_le_bytes());let d=Sha256::digest(&data[..n as usize]);for c in d.chunks_exact(8){sum=sum.wrapping_add(u64::from_le_bytes(c.try_into().unwrap()));}}
  else {let cv=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];let mut b=[0u32;16];for(i,v)in b.iter_mut().enumerate(){*v=(i as u32).wrapping_mul(0x1234567);}b[0]=r;let mut out=[0u32;16];unsafe{peer_blake3(cv.as_ptr(),b.as_ptr(),0,64,11,out.as_mut_ptr());}for v in out{sum=sum.wrapping_add(v as u64);}}
 }sum
}
