//! Offline bounded secure-trie prefix search; output remains untrusted advice.
use sha3::{Digest, Keccak256};
use std::sync::{atomic::{AtomicBool,AtomicU64,Ordering},Mutex};
use std::time::{Duration, Instant};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!((3..=5).contains(&args.len()));
    let prefix=&args[1];
    assert!(!prefix.is_empty() && prefix.len()<=7 && prefix.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    let seconds:u64=args[2].parse().unwrap();assert!((1..=60).contains(&seconds));
    let threads:usize=args.get(3).map(|v|v.parse().unwrap()).unwrap_or(4);assert!((1..=8).contains(&threads));
    let offset:u64=args.get(4).map(|v|v.parse().unwrap()).unwrap_or(0);assert!(offset.checked_add(1<<28).is_some());
    let wanted=u32::from_str_radix(prefix,16).unwrap();let shift=32-4*prefix.len();
    let started=Instant::now();let stop=AtomicBool::new(false);let next=AtomicU64::new(0);let total=AtomicU64::new(0);let found=Mutex::new(None);
    const MAX:u64=1<<28;const CHUNK:u64=1024;
    std::thread::scope(|scope|{
        for _ in 0..threads {
            let(stop,next,total,found)=(&stop,&next,&total,&found);
            scope.spawn(move||{
                let mut slot=[0u8;32];
                loop {
                    if stop.load(Ordering::Relaxed) || started.elapsed()>=Duration::from_secs(seconds){stop.store(true,Ordering::Relaxed);return;}
                    let begin=next.fetch_add(CHUNK,Ordering::Relaxed);if begin>=MAX{return;}
                    let mut count=0;
                    for local in begin..(begin+CHUNK).min(MAX) {
                        let candidate=offset+local;
                        if stop.load(Ordering::Relaxed){break;}
                        slot[24..].copy_from_slice(&candidate.to_be_bytes());let hash=Keccak256::digest(slot);count+=1;
                        if u32::from_be_bytes(hash[..4].try_into().unwrap())>>shift==wanted {
                            let mut result=found.lock().unwrap();if result.is_none(){*result=Some(candidate);}stop.store(true,Ordering::Relaxed);break;
                        }
                    }
                    total.fetch_add(count,Ordering::Relaxed);
                }
            });
        }
    });
    let result=*found.lock().unwrap();
    if let Some(candidate)=result{
        println!("{{\"candidate\":{candidate},\"start_offset\":{offset},\"attempts\":{},\"threads\":{threads},\"seconds\":{}}}",total.load(Ordering::Relaxed),started.elapsed().as_secs_f64());
    } else {eprintln!("bounded search stopped after {} hashes",total.load(Ordering::Relaxed));std::process::exit(2);}
}

#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn independent_full_keccak_vectors() {
  assert_eq!(Keccak256::digest([0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8]).iter().map(|b|format!("{b:02x}")).collect::<String>(),"290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563");
  assert_eq!(Keccak256::digest([255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8,255u8]).iter().map(|b|format!("{b:02x}")).collect::<String>(),"a9c584056064687e149968cbab758a3376d22aedc6a55823d1b3ecbee81b8fb9");
  assert_eq!(Keccak256::digest([0u8,1u8,2u8,3u8,4u8,5u8,6u8,7u8,8u8,9u8,10u8,11u8,12u8,13u8,14u8,15u8,16u8,17u8,18u8,19u8,20u8,21u8,22u8,23u8,24u8,25u8,26u8,27u8,28u8,29u8,30u8,31u8]).iter().map(|b|format!("{b:02x}")).collect::<String>(),"8ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd2d");
  assert_eq!(Keccak256::digest([128u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8]).iter().map(|b|format!("{b:02x}")).collect::<String>(),"de3995408d4211c18871603faad2abbdd832ff9dfb97528065798ee20dc635bf");
  assert_eq!(Keccak256::digest([0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,0u8,1u8]).iter().map(|b|format!("{b:02x}")).collect::<String>(),"b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6");
 }
}
